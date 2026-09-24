const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const User = require("../models/User");
const { sendMessage, validateChatAccess } = require("../services/chatService");

/**
 * Authenticate a socket connection via JWT passed in handshake auth.
 * Like the HTTP authMiddleware, the user must still exist and be active,
 * and identity/role come from the database rather than the token alone.
 */
const authenticateSocket = async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token || socket.handshake.query?.token;

    if (!token) {
      console.error("❌ Socket auth failed: No token provided in handshake");
      return next(new Error("Authentication error: no token"));
    }

    const secret = process.env.JWT_ACCESS_SECRET;
    if (!secret) {
      console.error("❌ Critical: JWT_ACCESS_SECRET not set in environment");
      return next(
        new Error("Server configuration error: JWT_ACCESS_SECRET not set"),
      );
    }

    let decoded;
    try {
      decoded = jwt.verify(token, secret);
    } catch (jwtErr) {
      console.error("❌ JWT verification failed:", jwtErr.message);
      // Check if token is expired
      if (jwtErr.name === "TokenExpiredError") {
        return next(new Error("Authentication error: token expired"));
      }
      return next(new Error(`Authentication error: ${jwtErr.message}`));
    }

    // Validate decoded token has required fields
    if (!decoded.userId) {
      console.error("❌ Token missing userId property", decoded);
      return next(new Error("Authentication error: invalid token structure"));
    }

    const user = await User.findById(decoded.userId).select("role isActive");
    if (!user) {
      return next(new Error("Authentication error: user not found"));
    }
    if (!user.isActive) {
      return next(new Error("Authentication error: account is deactivated"));
    }

    socket.user = { userId: user._id.toString(), role: user.role };
    console.log(
      "✅ Socket authenticated - userId:",
      socket.user.userId,
      "role:",
      socket.user.role,
    );
    next();
  } catch (err) {
    console.error("❌ Socket auth error:", err.message);
    next(new Error("Authentication error: invalid token"));
  }
};

/**
 * Return the appointment room id from an event payload, or null if it is
 * missing or not a valid ObjectId string. The room id alone never grants
 * access; it only names the room to authorize against.
 */
const roomIdOf = (payload) => {
  const appointmentId = payload?.appointmentId;
  return typeof appointmentId === "string" && mongoose.isValidObjectId(appointmentId)
    ? appointmentId
    : null;
};

/**
 * Register all Socket.io event handlers on the given io instance.
 * Called once from server.js after the io server is created.
 */
const registerSocketHandlers = (io) => {
  // Apply JWT auth middleware to every socket connection
  io.use(authenticateSocket);

  io.on("connection", (socket) => {
    const { userId, role } = socket.user;
    console.log(
      `🔌 Socket connected: userId=${userId} role=${role} socketId=${socket.id}`,
    );

    /**
     * Client joins a room scoped to an appointment.
     * Only the appointment's patient or doctor may join (same rule as chat
     * history and send_message); otherwise "join_error" is emitted.
     * Event: "join_room"  payload: { appointmentId: string }
     */
    socket.on("join_room", async (payload) => {
      const appointmentId = roomIdOf(payload);
      if (!appointmentId) {
        console.warn(`⚠️ Server: join_room called without a valid appointmentId`);
        return socket.emit("join_error", { message: "Invalid appointment id" });
      }

      const allowed = await validateChatAccess({ appointmentId, userId, role });
      if (!allowed) {
        console.warn(
          `⛔ Server: ${role}:${userId} denied join for room ${appointmentId}`,
        );
        return socket.emit("join_error", { appointmentId, message: "Access denied" });
      }

      socket.join(appointmentId);
      console.log(
        `📥 Server: ${role}:${userId} joined room ${appointmentId}, socketId=${socket.id}`,
      );
      // Confirm to the joining client that they are now in the room
      socket.emit("room_joined", { appointmentId });
    });

    /**
     * Client leaves a room.
     * Event: "leave_room"  payload: { appointmentId: string }
     */
    socket.on("leave_room", (payload) => {
      const appointmentId = roomIdOf(payload);
      if (!appointmentId) {
        console.warn(`⚠️ Server: leave_room called without appointmentId`);
        return;
      }
      socket.leave(appointmentId);
      console.log(`🚪 Server: ${role}:${userId} left room ${appointmentId}`);
    });

    /**
     * Client sends a chat message.
     * Event: "send_message"  payload: { appointmentId, message }
     * Emits back: "new_message" to all sockets in the room (including sender)
     *             "send_error"  to sender on failure
     */
    socket.on("send_message", async ({ appointmentId, message }) => {
      try {
        console.log(`📮 Server: Received send_message from ${role}:${userId}`, {
          appointmentId,
          messageLength: message?.length || 0,
        });

        const result = await sendMessage({
          appointmentId,
          senderId: userId,
          senderRole: role,
          message,
        });

        if (result.status !== 201) {
          console.error(
            `❌ Server: sendMessage returned non-201 status:`,
            result.status,
          );
          return socket.emit("send_error", { message: result.data.message });
        }

        // Broadcast to everyone in the room (including sender)
        console.log(
          `📡 Server: Broadcasting new_message to room ${appointmentId}, messageId=`,
          result.data.chat._id,
        );
        io.to(appointmentId).emit("new_message", result.data.chat);
      } catch (err) {
        console.error(`❌ Server: send_message error:`, err.message);
        socket.emit("send_error", { message: "Failed to send message" });
      }
    });

    /**
     * Typing events are only relayed into a room this socket was authorized
     * to join via join_room; anything else is silently dropped.
     */
    const joinedRoomOf = (payload) => {
      const appointmentId = roomIdOf(payload);
      return appointmentId && socket.rooms.has(appointmentId) ? appointmentId : null;
    };

    /**
     * Notify room members that this user is typing.
     * Event: "typing"  payload: { appointmentId, isTyping }
     */
    socket.on("typing", (payload) => {
      const appointmentId = joinedRoomOf(payload);
      if (!appointmentId) return;
      const isTyping = payload.isTyping;
      console.log(
        `✏️ Server: Received typing event from ${role}:${userId}, appointmentId=${appointmentId}, isTyping=${isTyping}`,
      );
      socket.to(appointmentId).emit("user_typing", {
        userId,
        role,
        isTyping: !!isTyping,
        senderRole: role,
      });
    });

    /**
     * Notify room members that this user stopped typing.
     * Event: "stop_typing"  payload: { appointmentId }
     */
    socket.on("stop_typing", (payload) => {
      const appointmentId = joinedRoomOf(payload);
      if (!appointmentId) return;
      console.log(
        `✏️ Server: Received stop_typing event from ${role}:${userId}, appointmentId=${appointmentId}`,
      );
      socket.to(appointmentId).emit("user_typing", {
        userId,
        role,
        isTyping: false,
        senderRole: role,
      });
    });

    socket.on("disconnect", (reason) => {
      console.log(`❌ Socket disconnected: userId=${userId} reason=${reason}`);
    });
  });
};

module.exports = { registerSocketHandlers };

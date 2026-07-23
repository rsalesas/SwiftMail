import Foundation
import NIOCore
import Logging

/// Handler for SMTP XOAUTH2 authentication.
///
/// Success is a straight 235. Failure, however, arrives as a `334` continuation
/// carrying a base64-encoded JSON error payload (e.g. Gmail sends
/// `{"status":"400","schemes":"Bearer","scope":"https://mail.google.com/"}`).
/// Per the XOAUTH2 protocol the client must reply with an empty line, after
/// which the server sends the final `535` rejection. A handler that ignores the
/// `334` (as the generic PLAIN handler does) never completes and times out,
/// hiding the real authentication error from the caller.
final class XOAuth2AuthHandler: BaseSMTPHandler<AuthResult>, @unchecked Sendable {
    /// Decoded error payload from the 334 continuation, if one was received.
    private var continuationError: String?

    /// Process a response line from the server
    /// - Parameter response: The response line to process
    /// - Returns: Whether the handler is complete
    override func processResponse(_ response: SMTPResponse) -> Bool {
        if response.code >= 200 && response.code < 300 {
            promise.succeed(AuthResult(method: .xoauth2, success: true))
            return true
        }

        if response.code == 334 {
            // Failure continuation: decode the payload and acknowledge with an
            // empty line so the server sends its final rejection.
            let trimmed = response.message.trimmingCharacters(in: .whitespaces)
            if let data = Data(base64Encoded: trimmed),
               let decoded = String(data: data, encoding: .utf8) {
                continuationError = decoded
            } else if !trimmed.isEmpty {
                continuationError = trimmed
            }

            guard let context else {
                promise.fail(SMTPError.connectionFailed("Channel context is nil"))
                return true
            }
            var buffer = context.channel.allocator.buffer(capacity: 2)
            buffer.writeString("\r\n")
            context.writeAndFlush(NIOAny(buffer), promise: nil)
            return false // Wait for the final response
        }

        if response.code >= 400 {
            var message = response.message
            if let continuationError {
                message += " (\(continuationError))"
            }
            promise.succeed(AuthResult(method: .xoauth2, success: false, errorMessage: message))
            return true
        }

        return false // Not yet complete
    }

    // Current channel context for sending the continuation acknowledgment.
    // Captured in channelRead — protocol-extension hooks like handlerAdded are
    // not dynamically dispatched to subclasses of BaseSMTPHandler.
    private var context: ChannelHandlerContext?

    public override func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        self.context = context
        super.channelRead(context: context, data: data)
    }
}

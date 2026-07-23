import Foundation
import Testing
import NIOCore
import NIOEmbedded
@testable import SwiftMail

@Suite("XOAuth2AuthHandler")
struct XOAuth2AuthHandlerTests {

    /// Gmail rejects XOAUTH2 with a 334 continuation carrying a base64 JSON
    /// payload, then a final 535 after the client acks with an empty line.
    /// The handler must ack the 334 and complete with the real error instead
    /// of waiting for a timeout.
    @Test
    func rejectionVia334ContinuationCompletesWithError() async throws {
        let channel = EmbeddedChannel()
        let promise = channel.eventLoop.makePromise(of: AuthResult.self)
        let handler = XOAuth2AuthHandler(commandTag: "", promise: promise)
        try await channel.pipeline.addHandler(handler)

        let payload = #"{"status":"400","schemes":"Bearer","scope":"https://mail.google.com/"}"#
        let encoded = Data(payload.utf8).base64EncodedString()

        // 334 continuation → handler should ack with CRLF and keep waiting
        try channel.writeInbound(SMTPResponse(code: 334, message: encoded))
        let ack = try channel.readOutbound(as: ByteBuffer.self)
        #expect(ack.map { String(buffer: $0) } == "\r\n")

        // Final rejection → handler completes with a failure carrying both messages
        try channel.writeInbound(SMTPResponse(code: 535, message: "5.7.8 Username and Password not accepted."))
        let result = try await promise.futureResult.get()
        #expect(result.success == false)
        #expect(result.errorMessage?.contains("5.7.8") == true)
        #expect(result.errorMessage?.contains("\"status\":\"400\"") == true)

        _ = try? channel.finish()
    }

    @Test
    func successCompletesImmediately() async throws {
        let channel = EmbeddedChannel()
        let promise = channel.eventLoop.makePromise(of: AuthResult.self)
        let handler = XOAuth2AuthHandler(commandTag: "", promise: promise)
        try await channel.pipeline.addHandler(handler)

        try channel.writeInbound(SMTPResponse(code: 235, message: "2.7.0 Accepted"))
        let result = try await promise.futureResult.get()
        #expect(result.success == true)

        _ = try? channel.finish()
    }
}

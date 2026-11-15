// EMLByteOffsetTests.swift
// The parser cuts messages on bytes, not Characters.

import Testing
import Foundation
@testable import SwiftMail

@Suite("EML Parser byte offsets", .serialized, .tags(.mime), .timeLimit(.minutes(1)))
struct EMLByteOffsetTests {

    /// A multipart/mixed message with a base64 PDF, lines ending in `ending`.
    private func invoice(lineEnding ending: String, subject: String = "Invoice 1042") -> Data {
        let lines = [
            "From: Alice <alice@example.com>",
            "To: me@example.com",
            "Subject: \(subject)",
            "Date: Mon, 9 Nov 2026 10:00:00 +0000",
            "Message-ID: <inv1042@example.com>",
            "In-Reply-To: <order77@example.com>",
            "References: <start@example.com>",
            " <order77@example.com>",
            "MIME-Version: 1.0",
            "Content-Type: multipart/mixed; boundary=\"b1\"",
            "",
            "--b1",
            "Content-Type: text/plain; charset=utf-8",
            "",
            "Please find the invoice attached.",
            "--b1",
            "Content-Type: application/pdf; name=\"invoice.pdf\"",
            "Content-Disposition: attachment; filename=\"invoice.pdf\"",
            "Content-Transfer-Encoding: base64",
            "",
            "JVBERi0xLjQK",
            "--b1--",
            "",
        ]
        return Data(lines.joined(separator: ending).utf8)
    }

    @Test("A CRLF message's attachment decodes to its exact bytes")
    func crlfAttachment() throws {
        let message = try EMLParser.parse(invoice(lineEnding: "\r\n"))
        try #require(message.parts.count == 2)
        #expect(message.textBody == "Please find the invoice attached.")
        let pdf = message.parts[1]
        #expect(pdf.section.description == "2")
        #expect(pdf.filename == "invoice.pdf")
        #expect(pdf.decodedData() == Data("%PDF-1.4\n".utf8))
    }

    @Test("An LF-only message parses the same")
    func lfAttachment() throws {
        let message = try EMLParser.parse(invoice(lineEnding: "\n"))
        try #require(message.parts.count == 2)
        #expect(message.parts[1].decodedData() == Data("%PDF-1.4\n".utf8))
    }

    @Test("Multi-byte UTF-8 in the headers doesn't move the body")
    func utf8Headers() throws {
        let message = try EMLParser.parse(invoice(lineEnding: "\r\n", subject: "Facture n° 1042 — été"))
        #expect(message.subject == "Facture n° 1042 — été")
        #expect(message.parts[1].decodedData() == Data("%PDF-1.4\n".utf8))
    }

    @Test("In-Reply-To and References are read, folded or not")
    func threading() throws {
        let message = try EMLParser.parse(invoice(lineEnding: "\r\n"))
        #expect(message.header.messageId?.description == "<inv1042@example.com>")
        #expect(message.header.inReplyTo?.description == "<order77@example.com>")
        #expect(message.header.references?.map(\.description) == ["<start@example.com>", "<order77@example.com>"])
        #expect(message.header.additionalFields?["references"] == nil)
    }

    @Test("A Latin-1 8bit body no longer makes the message unparseable")
    func latin1Body() throws {
        var data = Data("""
        From: a@example.com\r
        Subject: Caf\r
        Content-Type: text/plain; charset=iso-8859-1\r
        Content-Transfer-Encoding: 8bit\r
        \r

        """.utf8)
        data.append(contentsOf: [0x43, 0x61, 0x66, 0xE9]) // "Café" in Latin-1
        let message = try EMLParser.parse(data)
        #expect(message.textBody == "Café")
    }

    @Test("A boundary string inside a line is content, not a delimiter")
    func delimiterOnlyAtLineStart() throws {
        let eml = """
        From: a@example.com\r
        Content-Type: multipart/mixed; boundary="xyz"\r
        \r
        --xyz\r
        Content-Type: text/plain\r
        \r
        The boundary is --xyz, as it happens.\r
        --xyz--\r

        """
        let message = try EMLParser.parse(Data(eml.utf8))
        try #require(message.parts.count == 1)
        #expect(message.textBody == "The boundary is --xyz, as it happens.")
    }

    @Test("Nested multiparts keep IMAP section numbers")
    func nestedSections() throws {
        let eml = """
        From: a@example.com\r
        Content-Type: multipart/mixed; boundary="outer"\r
        \r
        --outer\r
        Content-Type: multipart/alternative; boundary="inner"\r
        \r
        --inner\r
        Content-Type: text/plain\r
        \r
        Plain\r
        --inner\r
        Content-Type: text/html\r
        \r
        <p>HTML</p>\r
        --inner--\r
        --outer\r
        Content-Type: image/png\r
        Content-Disposition: attachment; filename="dot.png"\r
        Content-Transfer-Encoding: base64\r
        \r
        iVBORw0KGgo=\r
        --outer--\r

        """
        let message = try EMLParser.parse(Data(eml.utf8))
        #expect(message.parts.map(\.section.description) == ["1.1", "1.2", "2"])
        #expect(message.htmlBody == "<p>HTML</p>")
        #expect(message.parts[2].decodedData() == Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))
    }
}

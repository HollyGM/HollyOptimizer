// hollyoptimizer-ai
//
// Standalone helper invoked by the Python app as a subprocess (never linked
// into the main executable). It turns a deterministic, already-computed scan
// summary into a friendlier sentence using the on-device Apple Intelligence
// model (Foundation Models framework), when the framework, OS version and
// hardware make that available.
//
// Contract: read one JSON object from stdin, always print exactly one JSON
// object to stdout, always exit 0. Every failure mode (old OS, ineligible
// device, Apple Intelligence disabled, model still downloading, malformed
// input, generation error) is reported in the JSON body, never via stderr or
// a non-zero exit code, so the Python caller has a single, uniform place to
// read the result.
//
// The model only rephrases numbers Python already computed; it never decides
// what gets scanned or deleted. That decision stays 100% deterministic, in
// the existing Python safety policy.

import Foundation
import FoundationModels

struct Input: Decodable {
    let facts: String
}

struct Output: Encodable {
    var available: Bool
    var summary: String?
    var reason: String?
}

func emit(_ output: Output) -> Never {
    let encoder = JSONEncoder()
    if let data = try? encoder.encode(output), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print(#"{"available":false,"reason":"encode_failed"}"#)
    }
    exit(0)
}

let stdinData = FileHandle.standardInput.readDataToEndOfFile()
guard let input = try? JSONDecoder().decode(Input.self, from: stdinData),
      !input.facts.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
else {
    emit(Output(available: false, summary: nil, reason: "invalid_input"))
}

guard #available(macOS 26.0, *) else {
    emit(Output(available: false, summary: nil, reason: "os_too_old"))
}

let model = SystemLanguageModel.default
guard case .available = model.availability else {
    var reason = "unavailable"
    if case .unavailable(let cause) = model.availability {
        reason = "\(cause)"
    }
    emit(Output(available: false, summary: nil, reason: reason))
}

let instructions = """
Você reescreve, em português do Brasil, relatórios de limpeza de disco do \
macOS gerados pelo aplicativo HollyOptimizer. Produza de uma a duas frases \
curtas, em tom claro e tranquilizador, adequadas para um usuário não técnico. \
Preserve exatamente todos os números, tamanhos e contagens fornecidos, sem \
arredondar, estimar ou inventar nenhum valor novo. Nunca sugira excluir algo \
que não esteja descrito nos fatos fornecidos. Responda apenas com o texto \
final, sem títulos, sem markdown e sem aspas.
"""

let session = LanguageModelSession(model: model, instructions: instructions)

let semaphore = DispatchSemaphore(value: 0)
var finalOutput = Output(available: false, summary: nil, reason: "generation_failed")

Task {
    do {
        let response = try await session.respond(to: input.facts)
        let text = response.content.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty {
            finalOutput = Output(available: false, summary: nil, reason: "empty_response")
        } else {
            finalOutput = Output(available: true, summary: text, reason: nil)
        }
    } catch {
        finalOutput = Output(available: false, summary: nil, reason: "generation_failed")
    }
    semaphore.signal()
}

semaphore.wait()
emit(finalOutput)

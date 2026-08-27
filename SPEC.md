# Gantry Specification

## 1. Status and Scope

Gantry is a proposed control language for coordinating model-backed agents in
Mezzanine. It is named for the elevated structure spanning a factory floor:
Mezzanine is the harness and observation point, while Gantry describes and
directs the work below.

This initial specification is a scaffold. It establishes the intended scope;
later revisions will define concrete syntax and execution semantics.

## 2. Design Goals

Gantry programs SHOULD make agent work readable, explicit, and reviewable.
The language will provide:

- model and agent prompts as first-class operations;
- conventional control flow, including conditionals and iteration;
- explicit routing, retries, and handoffs between agent operations;
- structured values and inspectable operation results; and
- semantics that fit Mezzanine's visible action and approval model.

## 3. Terminology

**Station**: a named model-backed agent operation.

**Run**: an invocation of a station or operation.

**Route**: a conditional decision that selects subsequent work.

**Handoff**: an explicit transfer of a result to another station.

**Shift**: a bounded phase of work, including retries or refinement.

## 4. Open Design Work

The first language-design milestone must define lexical syntax, data types,
prompt interpolation, control-flow forms, error behavior, model-operation
contracts, and the boundary between Gantry execution and Mezzanine actions.

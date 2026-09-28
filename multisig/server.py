"""
Multisig HTTP server — exposes MultisigGate as JSON-RPC over HTTP.
"""
import asyncio
import json
import logging

from aiohttp import web

from .gate import Decision, MultisigGate, MultisigPolicy, RiskScorer, SigningParty, PartyType, ApprovalStatus

log = logging.getLogger("pmcp.multisig.server")


def create_multisig_app(gate: MultisigGate) -> web.Application:
    app = web.Application()
    app["gate"] = gate
    app["scorer"] = RiskScorer()
    app.router.add_post("/rpc", handle_rpc)
    app.router.add_get("/health", lambda r: web.json_response({"status": "ok"}))
    return app


async def handle_rpc(req: web.Request) -> web.Response:
    gate: MultisigGate = req.app["gate"]
    scorer: RiskScorer = req.app["scorer"]

    try:
        body = await req.json()
    except Exception:
        return web.json_response({"jsonrpc": "2.0", "id": None,
                                  "error": {"code": -32700, "message": "Parse error"}}, status=400)

    method = body.get("method", "")
    params = body.get("params", {})
    rpc_id = body.get("id")

    try:
        if method == "multisig/submit":
            risk = scorer.score(params.get("method", ""), params.get("params", {}))
            risk = max(risk, float(params.get("risk_score", 0)))
            approval_id = await gate.submit(
                params["robot_id"], params["method"], params.get("params", {}), risk
            )
            result = {"approval_id": approval_id, "risk_score": risk}

        elif method == "multisig/sign":
            status = await gate.sign(
                params["approval_id"], params["party_id"],
                Decision(params["decision"]), params.get("comment", "")
            )
            result = {"status": status.value}

        elif method == "multisig/list":
            status_filter = params.get("status")
            sf = ApprovalStatus(status_filter) if status_filter else None
            result = {"approvals": gate.list_approvals(sf)}

        elif method == "multisig/status":
            detail = gate.get_approval(params["approval_id"])
            if detail is None:
                return web.json_response(
                    {"jsonrpc": "2.0", "id": rpc_id,
                     "error": {"code": -32602, "message": "Not found"}})
            result = detail

        elif method == "multisig/policies":
            result = {"policies": gate.list_policies()}

        elif method == "multisig/add_party":
            gate.add_party(SigningParty(
                params["party_id"], params["name"],
                PartyType(params["party_type"]), params.get("public_key", "")
            ))
            result = {"ok": True}

        elif method == "multisig/set_policy":
            gate.set_policy(MultisigPolicy(
                params["policy_id"], params["name"],
                float(params["risk_threshold"]),
                int(params["required_human_approvals"]),
                int(params.get("required_ai_approvals", 0)),
                float(params.get("timeout_s", 300)),
            ))
            result = {"ok": True}

        else:
            return web.json_response(
                {"jsonrpc": "2.0", "id": rpc_id,
                 "error": {"code": -32601, "message": f"Unknown method: {method}"}})

        return web.json_response({"jsonrpc": "2.0", "id": rpc_id, "result": result})

    except Exception as exc:
        log.exception("Multisig RPC error: %s", exc)
        return web.json_response(
            {"jsonrpc": "2.0", "id": rpc_id,
             "error": {"code": -32603, "message": str(exc)}})


async def main(port: int = 9003) -> None:
    logging.basicConfig(level=logging.INFO)
    gate = MultisigGate()
    app = create_multisig_app(gate)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", port).start()
    log.info("Multisig gate running on port %d", port)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())

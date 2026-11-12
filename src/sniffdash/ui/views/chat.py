"""Ask AI tab (Reqs 31–34): questions in, answers with VERIFIED frame evidence out.

State (audit A2, A7): the chat history lives in ``st.session_state`` under the
capture fingerprint (bytes + parser + packet limit), so each parse of each file
has its own conversation. A failed question (quota, auth, network) is stored as
failed and shown in-line; it never erases earlier answers.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd
import streamlit as st

from sniffdash.application import AnalysisSession
from sniffdash.domain.errors import LLMAuthError, LLMError, LLMRateLimitError
from sniffdash.llm.answer import SkillLevel, ValidatedAnswer, parse_ts
from sniffdash.ui.registry import ResultView, ViewContext, register_view

SERVICE_OVERRIDE_KEY = "sniffdash_llm_service"  # tests inject a scripted service here
HISTORY_KEY = "sniffdash_chat"
LEVELS = [level.value for level in SkillLevel]

PRIVACY_NOTE = ("Questions are answered by Google Gemini. SniffDash sends a summary of this capture (statistics, "
                "hosts, URIs, timings) and, when needed, single transactions with cookies, auth headers and "
                "password fields redacted.")


@dataclass
class ChatTurn:
    question: str
    level: str
    answer: ValidatedAnswer | None = None
    error: str | None = None


def history(fingerprint: str) -> list[ChatTurn]:
    return st.session_state.setdefault(HISTORY_KEY, {}).setdefault(fingerprint, [])


def friendly(exc: Exception) -> str:
    if isinstance(exc, LLMRateLimitError):
        return f"Quota reached: {exc}"
    if isinstance(exc, LLMAuthError):
        return f"API key problem: {exc}"
    if isinstance(exc, (LLMError, ValueError)):
        return str(exc)
    return f"Unexpected error: {type(exc).__name__}: {exc}"


def evidence_frame(session: AnalysisSession, answer: ValidatedAnswer) -> pd.DataFrame:
    rows = []
    for e in answer.valid_evidence:
        tx = session.transaction_for_frame(e.frame_number)
        info = session.frame_info(e.frame_number) or {}
        rows.append({"frame": e.frame_number, "time_utc": e.timestamp,
                     "rel_s": session.relative(parse_ts(e.timestamp)),
                     "transaction": tx.id if tx else None,          # A10: non-HTTP evidence has none
                     "protocols": info.get("protocols"), "claim": e.claim})
    return pd.DataFrame(rows, columns=["frame", "time_utc", "rel_s", "transaction", "protocols", "claim"])


def render_turn(session: AnalysisSession, turn: ChatTurn, index: int) -> None:
    with st.chat_message("user"):
        st.markdown(turn.question)
        st.caption(f"level: {turn.level}")
    with st.chat_message("assistant"):
        if turn.error:
            st.error(turn.error)
            return
        answer = turn.answer
        st.markdown(answer.answer)
        if answer.insufficient_data:
            st.info("The capture does not contain enough data to answer this fully.")
        if answer.invalid_citations:
            st.warning("**Unverified citations**: these did NOT match the capture and should not be trusted:\n"
                       + "\n".join(f"- frame {c.frame_number}: {c.reason}" for c in answer.invalid_citations))
        if answer.valid_evidence:
            st.caption(f"Evidence: {len(answer.valid_evidence)} citation(s), each verified against the capture")
            df = evidence_frame(session, answer)
            st.dataframe(df, hide_index=True, width="stretch", key=f"evidence_{session.fingerprint}_{index}",
                         column_config={"rel_s": st.column_config.NumberColumn("Rel. s", format="%.3f")})
            for tx_id in dict.fromkeys(t for t in df["transaction"] if t):
                with st.expander(f"Show stream {tx_id}"):
                    view = session.stream(tx_id)
                    st.code(view.request_text, language="http", wrap_lines=True)
                    st.code(view.response_text, language="http", wrap_lines=True)
        if answer.tools_used:
            st.caption("Looked up: " + ", ".join(dict.fromkeys(answer.tools_used)))


@register_view
class ChatView(ResultView):
    title = "Ask AI"
    order = 40

    def render(self, ctx: ViewContext) -> None:
        session = ctx.session
        service = st.session_state.get(SERVICE_OVERRIDE_KEY) or ctx.services.llm
        if service is None:
            st.warning(f"AI answers are not available: {ctx.services.llm_unavailable_reason}")
            st.markdown("1. Get a free key at https://aistudio.google.com/apikey\n"
                        "2. Copy `.env.example` to `.env` and set `GEMINI_API_KEY=...`\n"
                        "3. Restart the dashboard (`streamlit run app.py`).")
            return

        level = st.segmented_control("Explanation level", LEVELS, default=SkillLevel.INTERMEDIATE.value,
                                     key="sniffdash_skill_level") or SkillLevel.INTERMEDIATE.value
        st.caption(PRIVACY_NOTE)

        turns = history(session.fingerprint)
        messages = st.container()
        question = st.chat_input("Ask about this capture, e.g. “Which HTTP request was the slowest?”")
        if question:
            turn = ChatTurn(question=question, level=level)
            try:
                with st.spinner("Looking it up…"):
                    turn.answer = session.ask(question, level, service)
            except Exception as exc:  # A7: recorded as failed; earlier answers stay
                turn.error = friendly(exc)
            turns.append(turn)

        with messages:
            if not turns:
                st.caption("Try: *Which HTTP request was the slowest?* · *How many requests went to example.com?* · "
                           "*Which status codes were returned?* · *Explain transaction tx-4.*")
            for i, turn in enumerate(turns):
                render_turn(session, turn, i)

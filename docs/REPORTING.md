# Aggregate report evidence and compatibility

Rspamd 4.2.1 stores actual DMARC evaluations in Redis and emits MIME with an `application/gzip`
XML attachment through receiver Postfix to local reports@recipient.test, captured in Mailpit.
Cross-domain report permission is published at `sender.test._report._dmarc.recipient.test` and its
lookalike equivalent. Nothing is sent to an external report collector.

`tools/reports.py` preserves a Redis RDB snapshot before the upstream generator consumes report
keys, saves the raw delivered MIME and decoded XML, then hashes the bundle. The parser bounds both
MIME and decompression to 2 MiB, requires UTF-8 without NUL, prohibits DTD/entities and never follows
links. It is a parser for this selected legacy format, not a general DMARC ingestion service.

The exclusive final window `evidence/report-window-03` contains S01, S02 and S11. Two real reports
in `evidence/reports-controlled-final` count exactly three messages: sender.test/.10 aligned pass,
sender.test/.11 aligned fail, lookalike.test/.10 aligned pass. The report range is Unix UTC
**1790997683–1790997723**. `evidence/report-correlation-final.json` verifies source IPs, counts,
results, dispositions and enclosure of the actual receiver timestamps. The nine-case replay report
also correlates exactly: `evidence/replay-report-correlation.json`.

## Current-window adapter

Upstream `rspamadm dmarc_report YYYYMMDD` selects that day's Redis keys but computes its report
end at today's midnight; merely selecting today's date does not produce a same-day metadata range.
`reports-controlled-01` demonstrates the unsuitable previous-day labels and remains preserved.
An initial Lua interpreter invocation timed out; `reports-controlled-02` remains an incomplete attempt.

For a bounded current-day exercise, `--begin EPOCH` uses a separate upstream command copy with two
explicit edits: change `start_collection = today_midnight()` to `os.time()`, and rename the command
to `peal_report`. It leaves the installed upstream command untouched, preserves original/adapted
sources and prior Redis collection metadata, and uses the normal Rspamd report transport/event loop.
The begin value is the real control-window start, never a fabricated message timestamp. This is a
documented lab deviation, not unmodified upstream behavior. Preserve the Apache-2.0 license/notice
with these copied Lua artifacts. See `evidence/licenses/Apache-2.0.txt`.

Run serially, first collect any accumulated data, then set a real UTC begin time, run an exclusive
window, and collect with that begin. Use `tools/correlate_reports.py` to check the exact window.
Its controlled-window identity model requires exact alignment; it is not a generic relaxed-alignment
or policy-override analyzer. Daily production scheduling is outside this deliverable.

## Standards versus implementation

[RFC 9989](https://datatracker.ietf.org/doc/html/rfc9989) removes the legacy pct policy tag. The
selected Rspamd source still samples with pct. This lab does not enable sampling or claim full
implementation of RFC 9989's policy-discovery changes.

[RFC 9990 Appendix A](https://datatracker.ietf.org/doc/html/rfc9990#appendix-A) defines namespace
`urn:ietf:params:xml:ns:dmarc-2.0`. Actual selected reports have an unnamespaced `<feedback>` root
and `<pct>100</pct>` in policy_published; that pct field is absent from the current schema.
These concrete differences establish a legacy reporting format, not full RFC 9990 schema compatibility.
No complete XSD validation or cross-product interoperability test was run. Correct counts and XML
parsing do not prove standards conformance. Report policy/disposition fields also do not replace
independently verified hold queues and SMTP rejections.

## Review verification

The fresh `evidence/review-01/report-window` and `reports` bundles repeat the exact three-message/two-report control at UTC 1790999960–1791000006. `report-correlation.json` passed with row header identity and ordered integer time bounds now required. Reports require the shared isolation gate before collection/generation. Prior reports remain immutable historical evidence.

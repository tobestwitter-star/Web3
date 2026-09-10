from __future__ import annotations
import re
from dataclasses import dataclass, asdict

@dataclass(frozen=True)
class SourceContext:
    file: str | None
    contract: str | None
    function: str | None
    modifier: str | None
    line: int | None
    line_end: int | None
    certainty: str
    reason: str

    def to_dict(self):
        return asdict(self)

class SourceAttributor:
    """Map a finding to the smallest source construct actually containing its evidence.

    The analyzer often receives concatenated sources prefixed with ``// FILE:``.  This
    parser deliberately refuses to infer a contract/function from a nearby declaration:
    containment in brace spans is required.  If containment cannot be established, the
    result is explicitly uncertain.
    """
    FILE_RE = re.compile(r"^\s*//\s*FILE:\s*(.+?)\s*$", re.M)
    CONTRACT_RE = re.compile(r"\b(?:contract|abstract\s+contract|library|interface)\s+(\w+)\s*(?:is\s+[^\{]+)?\{", re.I)
    FUNCTION_RE = re.compile(r"\bfunction\s+(\w+)\s*\([^)]*\)[^\{;]*\{", re.I)
    MODIFIER_RE = re.compile(r"\bmodifier\s+(\w+)\s*\([^)]*\)[^\{;]*\{", re.I)

    def __init__(self, code: str):
        self.code = code
        self.lines = code.splitlines()
        self.files = self._spans(self.FILE_RE, named=False)
        self.contracts = self._spans(self.CONTRACT_RE, named=True)
        self.functions = self._spans(self.FUNCTION_RE, named=True)
        self.modifiers = self._spans(self.MODIFIER_RE, named=True)

    def _brace_end(self, start: int) -> int:
        depth = 0
        i = start
        while i < len(self.code):
            ch = self.code[i]
            if ch == '{': depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0: return i + 1
            i += 1
        return len(self.code)

    def _spans(self, regex, named=True):
        out=[]
        for m in regex.finditer(self.code):
            end=self._brace_end(m.end()-1)
            out.append({'start':m.start(),'end':end,'name':m.group(1) if named else m.group(1).strip()})
        return out

    def _line(self, pos: int) -> int:
        return self.code.count('\n', 0, max(0,pos)) + 1

    def _span_at(self, spans, pos):
        matches=[s for s in spans if s['start'] <= pos < s['end']]
        return min(matches, key=lambda s:s['end']-s['start']) if matches else None

    def _file_at(self, pos):
        markers=list(self.FILE_RE.finditer(self.code))
        current=None
        for m in markers:
            if m.start() <= pos: current=m.group(1).strip()
            else: break
        return current

    def context_at(self, pos: int) -> SourceContext:
        pos=max(0,min(len(self.code)-1,pos)) if self.code else 0
        fn=self._span_at(self.functions,pos)
        mod=self._span_at(self.modifiers,pos)
        container=self._span_at(self.contracts,pos)
        chosen=fn or mod
        line=self._line(pos) if self.code else None
        return SourceContext(
            file=self._file_at(pos),
            contract=container['name'] if container else None,
            function=fn['name'] if fn else None,
            modifier=mod['name'] if mod else None,
            line=line,
            line_end=self._line((chosen['end']-1) if chosen else pos) if self.code else None,
            certainty='exact' if chosen and container else ('function_exact' if chosen else 'uncertain'),
            reason='Position is contained by the reported Solidity function/modifier and contract.' if chosen and container else ('Position is contained by a Solidity function/modifier, but no containing contract was established.' if chosen else 'No containing function/modifier span could be established; location must not be presented as precise.')
        )

    def evidence_position(self, location='', evidence=None, preferred_patterns=()):
        m=re.search(r'\bline\s+(\d+)',str(location or ''),re.I)
        if m:
            line=int(m.group(1)); return sum(len(x)+1 for x in self.lines[:max(0,line-1)])
        text=' '.join(evidence) if isinstance(evidence,list) else str(evidence or '')
        for pat in preferred_patterns:
            em=re.search(pat,text,re.I)
            if em:
                pos=self.code.find(em.group(0))
                if pos>=0:return pos
        return None

    def attribute(self, finding: dict) -> dict:
        pos=self.evidence_position(finding.get('location'),finding.get('evidence'),(
            r'\b\w+\s*\.\s*(?:call|send|transfer)\b',
            r'\b(?:delegatecall|ecrecover)\s*\(',
            r'\b(?:state|status|owner|admin|balance\w*|shares|debt|nonce)\w*\s*(?:=|\+=|-=)',
        ))
        ctx=self.context_at(pos) if pos is not None else SourceContext(None,None,None,None,None,None,'uncertain','No reliable source position was available.')
        out=dict(finding)
        out['source_attribution']=ctx.to_dict()
        if ctx.file: out['file']=ctx.file
        if ctx.contract: out['contract']=ctx.contract
        if ctx.function: out['function']=ctx.function
        if ctx.modifier: out['modifier']=ctx.modifier
        out['attribution_status']=ctx.certainty
        out['location_uncertain']=ctx.certainty=='uncertain'
        return out


def attribute_findings(code: str, findings):
    a=SourceAttributor(code)
    return [a.attribute(f) for f in findings]

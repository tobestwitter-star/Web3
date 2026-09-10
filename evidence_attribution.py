from __future__ import annotations
import re
from dataclasses import dataclass, asdict

@dataclass(frozen=True)
class SourceContext:
    file: str | None
    contract: str | None
    function: str | None
    modifier: str | None
    mutability: str | None
    line: int | None
    line_end: int | None
    certainty: str
    reason: str
    evidence_line: int | None = None
    evidence_line_end: int | None = None
    def to_dict(self): return asdict(self)

class SourceAttributor:
    FILE_RE=re.compile(r"^\s*//\s*FILE:\s*(.+?)\s*$",re.M)
    CONTRACT_RE=re.compile(r"\b(?:contract|abstract\s+contract|library|interface)\s+(\w+)\s*(?:is\s+[^\{]+)?\{",re.I)
    FUNCTION_RE=re.compile(r"\bfunction\s+(\w+)\s*\([^)]*\)([^\{;]*)\{",re.I)
    MODIFIER_RE=re.compile(r"\bmodifier\s+(\w+)\s*\([^)]*\)[^\{;]*\{",re.I)
    def __init__(self,code):
        self.code=code; self.lines=code.splitlines(); self.files=self._spans(self.FILE_RE,False); self.contracts=self._spans(self.CONTRACT_RE,True); self.functions=self._spans(self.FUNCTION_RE,True); self.modifiers=self._spans(self.MODIFIER_RE,True)
    def _brace_end(self,start):
        depth=0
        for i in range(start,len(self.code)):
            if self.code[i]=='{': depth+=1
            elif self.code[i]=='}':
                depth-=1
                if depth==0:return i+1
        return len(self.code)
    def _spans(self,regex,named=True):
        out=[]
        for m in regex.finditer(self.code):
            e={'start':m.start(),'end':self._brace_end(m.end()-1),'name':m.group(1).strip()}
            if regex is self.FUNCTION_RE:
                tail=m.group(2).lower(); e['mutability']='view' if re.search(r'\bview\b',tail) else ('pure' if re.search(r'\bpure\b',tail) else ('payable' if re.search(r'\bpayable\b',tail) else 'nonpayable'))
            out.append(e)
        return out
    def _line(self,pos): return self.code.count('\n',0,max(0,pos))+1
    def _span_at(self,spans,pos):
        hits=[s for s in spans if s['start']<=pos<s['end']]; return min(hits,key=lambda s:s['end']-s['start']) if hits else None
    def _file_at(self,pos):
        cur=None
        for m in self.FILE_RE.finditer(self.code):
            if m.start()<=pos: cur=m.group(1).strip()
            else: break
        return cur
    def context_at(self,pos,evidence_start=None,evidence_end=None):
        pos=max(0,min(len(self.code)-1,pos)) if self.code else 0; fn=self._span_at(self.functions,pos); mod=self._span_at(self.modifiers,pos); container=self._span_at(self.contracts,pos); chosen=fn or mod
        return SourceContext(self._file_at(pos),container['name'] if container else None,fn['name'] if fn else None,mod['name'] if mod else None,fn.get('mutability') if fn else None,self._line(pos) if self.code else None,self._line(chosen['end']-1 if chosen else pos) if self.code else None,'exact' if chosen and container else ('function_exact' if chosen else 'uncertain'),'Evidence position is contained by the reported function/modifier and contract.' if chosen and container else ('Evidence is inside a function/modifier but no containing contract was established.' if chosen else 'No containing function/modifier span could be established; precision is explicitly uncertain.'),self._line(evidence_start) if evidence_start is not None else None,self._line(max(evidence_start,evidence_end-1)) if evidence_start is not None and evidence_end is not None else None)
    def evidence_position(self,location='',evidence=None,preferred_patterns=()):
        m=re.search(r'\bline\s+(\d+)',str(location or ''),re.I)
        if m:
            line=int(m.group(1)); return sum(len(x)+1 for x in self.lines[:max(0,line-1)]),None
        items=evidence if isinstance(evidence,list) else [evidence]
        for item in items:
            text=str(item or '').strip()
            if len(text)>=24:
                p=self.code.find(text)
                if p>=0:return p,p+len(text)
        joined=' '.join(str(x or '') for x in items)
        for pat in preferred_patterns:
            em=re.search(pat,joined,re.I)
            if em:
                p=self.code.find(em.group(0))
                if p>=0:return p,p+len(em.group(0))
        return None,None
    def attribute(self,finding):
        pos,eend=self.evidence_position(finding.get('location'),finding.get('evidence'),(r'\b\w+\s*\.\s*(?:call|send|transfer)\b',r'\b(?:delegatecall|ecrecover)\s*\(',r'\b(?:state|status|owner|admin|balance\w*|shares|debt|nonce)\w*\s*(?:=|\+=|-=)',))
        ctx=self.context_at(pos,evidence_start=pos,evidence_end=eend) if pos is not None else SourceContext(None,None,None,None,None,None,None,'uncertain','No reliable source position was available.')
        out=dict(finding); out['source_attribution']=ctx.to_dict(); out['attribution_status']=ctx.certainty; out['location_uncertain']=ctx.certainty=='uncertain'
        for k in ('file','contract','function','modifier'):
            v=getattr(ctx,k)
            if v: out[k]=v
        return out

def attribute_findings(code,findings): return [SourceAttributor(code).attribute(f) for f in findings]

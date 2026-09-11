"""Public, rate-limit-friendly historical finding intelligence.

Search is limited to legitimate public sources explicitly configured by the caller.
Results are similarity leads, never automatic duplicate decisions.
"""
from __future__ import annotations
import hashlib,re
from typing import Any,Dict,List,Optional
from urllib.parse import quote

class HistoricalIntelligence:
    SOURCES={
      'github_code_search':'https://github.com/search?q={query}+smart+contract+audit&type=code',
      'google_github':'https://www.google.com/search?q=site%3Agithub.com+{query}+audit+vulnerability',
      'defi_hacklabs':'https://github.com/SunWeb3Sec/DeFiHackLabs/search?q={query}&type=code',
    }
    def _tokens(self,text:str)->set[str]:
        return {x for x in re.findall(r'[a-z0-9]{4,}',text.lower()) if x not in {'function','contract','solidity','smart','audit','vulnerability'}}
    def fingerprint(self,finding:Dict[str,Any])->str:
        text=' '.join(str(finding.get(k,'')) for k in ('title','category','description','hypothesis','root_cause','location'))
        normalized=' '.join(sorted(self._tokens(text)))
        return hashlib.sha256(normalized.encode('utf-8')).hexdigest()
    def similarity(self,a:str,b:str)->float:
        x,y=self._tokens(a),self._tokens(b)
        return round(len(x&y)/max(1,len(x|y)),3)
    def search_urls(self,title:str,category:str,source_names:Optional[List[str]]=None)->List[Dict[str,Any]]:
        q=quote(f'"{title}" {category}',safe='')
        out=[]
        for name in source_names or list(self.SOURCES):
            if name not in self.SOURCES: continue
            out.append({'source':name,'url':self.SOURCES[name].format(query=q),'query':f'{title} {category}','status':'candidate-public-search','requires_human_review':True})
        return out
    def compare(self,finding:Dict[str,Any],historical:List[Dict[str,Any]])->List[Dict[str,Any]]:
        current=' '.join(str(finding.get(k,'')) for k in ('title','category','description','hypothesis','root_cause'))
        current_fp=self.fingerprint(finding);matches=[]
        for item in historical:
            text=' '.join(str(item.get(k,'')) for k in ('title','category','description','summary','root_cause'))
            sim=self.similarity(current,text)
            exact=current_fp==self.fingerprint(item)
            if exact or sim>=.18:
                matches.append({'reference':item,'similarity':1.0 if exact else sim,'match_type':'exact_normalized_fingerprint' if exact else 'semantic_similarity_lead','duplicate_decision':'POSSIBLE DUPLICATE — HUMAN REVIEW REQUIRED'})
        return sorted(matches,key=lambda x:x['similarity'],reverse=True)

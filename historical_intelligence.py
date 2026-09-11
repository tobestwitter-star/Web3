"""Public historical finding intelligence with explicit source invocation.

Historical evidence is contextual only. Exact fingerprints and semantic leads are
kept separate and every match remains human-review gated.
"""
from __future__ import annotations
import hashlib,json,re,urllib.request
from typing import Any,Dict,List,Optional
from urllib.parse import quote

class HistoricalIntelligence:
    SOURCES={
      'github_code_search':'https://github.com/search?q={query}+smart+contract+audit&type=code',
      'google_github':'https://www.google.com/search?q=site%3Agithub.com+{query}+audit+vulnerability',
      'defi_hacklabs':'https://github.com/SunWeb3Sec/DeFiHackLabs/search?q={query}&type=code',
    }
    DEFI_REPO='https://api.github.com/repos/SunWeb3Sec/DeFiHackLabs/git/trees/main?recursive=1'
    DEFI_RAW='https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/'
    def _tokens(self,text:str)->set[str]:
        return {x for x in re.findall(r'[a-z0-9]{4,}',text.lower()) if x not in {'function','contract','solidity','smart','audit','vulnerability','uint256','address'}}
    def fingerprint(self,finding:Dict[str,Any])->str:
        text=' '.join(str(finding.get(k,'')) for k in ('title','category','description','hypothesis','root_cause','location'))
        normalized=' '.join(sorted(self._tokens(text)))
        return hashlib.sha256(normalized.encode('utf-8')).hexdigest()
    def similarity(self,a:str,b:str)->float:
        x,y=self._tokens(a),self._tokens(b)
        return round(len(x&y)/max(1,len(x|y)),3)
    def search_urls(self,title:str,category:str,source_names:Optional[List[str]]=None)->List[Dict[str,Any]]:
        q=quote(f'"{title}" {category}',safe='')
        return [{'source':name,'url':self.SOURCES[name].format(query=q),'query':f'{title} {category}','status':'candidate-public-search','requires_human_review':True} for name in (source_names or list(self.SOURCES)) if name in self.SOURCES]
    def _get_json(self,url:str,timeout:int=8)->Any:
        req=urllib.request.Request(url,headers={'User-Agent':'Web3-BugHunter/1.0','Accept':'application/vnd.github+json'})
        with urllib.request.urlopen(req,timeout=timeout) as r:return json.loads(r.read().decode('utf-8','replace'))
    def _get_text(self,url:str,timeout:int=8)->str:
        req=urllib.request.Request(url,headers={'User-Agent':'Web3-BugHunter/1.0'})
        with urllib.request.urlopen(req,timeout=timeout) as r:return r.read().decode('utf-8','replace')
    def search_defi_hacklabs(self,finding:Dict[str,Any],max_records:int=5)->List[Dict[str,Any]]:
        """Invoke the public DeFiHackLabs corpus and return bounded historical leads."""
        query_tokens=list(self._tokens(' '.join(str(finding.get(k,'')) for k in ('title','category','description','root_cause'))))[:8]
        if not query_tokens:return []
        try:tree=self._get_json(self.DEFI_REPO,10).get('tree',[])
        except Exception:return []
        candidates=[]
        for item in tree:
            path=str(item.get('path',''))
            if item.get('type')!='blob' or not path.endswith(('.sol','.md','.json')):continue
            score=sum(1 for token in query_tokens if token in path.lower())
            if score:candidates.append((score,path))
        candidates=sorted(candidates,key=lambda x:(-x[0],len(x[1])))[:max_records]
        records=[]
        for score,path in candidates:
            try:text=self._get_text(self.DEFI_RAW+quote(path,safe='/._-'),8)
            except Exception:continue
            records.append({'source':'defi_hacklabs','reference':self.DEFI_RAW+quote(path,safe='/._-'),'title':path,'category':finding.get('category',''),'description':text[:12000],'source_match_score':score,'historical_corpus':'DeFiHackLabs','requires_human_review':True})
        return records
    def lookup(self,finding:Dict[str,Any],source_names:Optional[List[str]]=None,max_records:int=5)->Dict[str,Any]:
        selected=source_names or ['defi_hacklabs','github_code_search']
        records=[];invocations=[]
        if 'defi_hacklabs' in selected:
            invocations.append({'source':'defi_hacklabs','invoked':True,'bounded':True})
            records.extend(self.search_defi_hacklabs(finding,max_records))
        for lead in self.search_urls(finding.get('title',''),finding.get('category',''),[x for x in selected if x!='defi_hacklabs']):
            invocations.append({'source':lead['source'],'invoked':True,'bounded':True,'query':lead['query'],'url':lead['url']})
        matches=self.compare(finding,records)
        return {'invocations':invocations,'records_considered':len(records),'matches':matches,'review_status':'POSSIBLE DUPLICATE — HUMAN REVIEW REQUIRED' if matches else 'No historical match established; human review required.','historical_evidence_only':True}
    def compare(self,finding:Dict[str,Any],historical:List[Dict[str,Any]])->List[Dict[str,Any]]:
        current=' '.join(str(finding.get(k,'')) for k in ('title','category','description','hypothesis','root_cause'))
        current_fp=self.fingerprint(finding);matches=[]
        for item in historical:
            text=' '.join(str(item.get(k,'')) for k in ('title','category','description','summary','root_cause'))
            sim=self.similarity(current,text);exact=current_fp==self.fingerprint(item)
            if exact or sim>=.18:
                matches.append({'reference':item,'similarity':1.0 if exact else sim,'match_type':'exact_normalized_fingerprint' if exact else 'semantic_similarity_lead','duplicate_decision':'POSSIBLE DUPLICATE — HUMAN REVIEW REQUIRED'})
        return sorted(matches,key=lambda x:x['similarity'],reverse=True)

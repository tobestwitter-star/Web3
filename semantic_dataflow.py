from __future__ import annotations
import re
STATUS='UNVERIFIED — HUMAN REVIEW REQUIRED'
class SemanticDataflow:
    def _functions(self, code):
        out=[]
        for m in re.finditer(r'\bfunction\s+(\w+)\s*\(([^)]*)\)([^\{;]*)\{',code,re.I):
            depth=1;i=m.end()
            while i<len(code) and depth:
                if code[i]=='{': depth+=1
                elif code[i]=='}': depth-=1
                i+=1
            out.append((m,m.group(1),m.group(2),m.group(3),code[m.end():max(m.end(),i-1)]))
        return out
    def _finding(self,cat,title,sev,code,pos,desc,evidence,conf=.78):
        return {'title':title,'severity':sev,'category':cat,'location':f"Source evidence near line {code[:pos].count(chr(10))+1}",'description':desc,'confidence':conf,'evidence':[evidence[:2200]],'status':STATUS}
    def _auth(self,head,body):
        s=head+' '+body
        if re.search(r'\b(?:onlyOwner|onlyRole|hasRole|authorized|isOwner|_authorizeUpgrade|nonReentrant|gate|auth)\b',s,re.I): return True
        return bool(re.search(r'\brequire\s*\([^;\n]{0,260}\bmsg\.sender\b',s,re.I))
    def _state_write(self,b):
        return re.search(r'\b(?:balance|balances|shares|debt|state|status|phase|mode|owner|admin|controller|governor|implementation|logic|total|reserve|credits|quota|nonce)\w*(?:\s*\[[^\]]+\])?\s*(?:=|\+=|-=|\*=|\+\+|--)',b,re.I)
    def analyze(self,code,name='target'):
        fs=[];funcs=self._functions(code);interfaces={}
        for im in re.finditer(r'interface\s+(\w+)\s*\{(.*?)\}',code,re.I|re.S):
            interfaces[im.group(1)]={m.group(1) for m in re.finditer(r'function\s+(\w+)\s*\([^)]*\)\s*([^;]*);',im.group(2),re.I) if not re.search(r'\b(?:view|pure)\b',m.group(2),re.I)}
        iface_vars=set()
        for typ,var in re.findall(r'\b(\w+)\s+(?:public|private|internal)?\s*(\w+)\s*;',code):
            if typ in interfaces: iface_vars.add(var)
        external_patterns=r'(?:address\s*\([^)]*\)|\w+)\s*\.\s*(?:call|send|transfer)\s*(?:\{|\()'
        for m,n,a,h,b in funcs:
            calls=list(re.finditer(external_patterns,b,re.I))
            for iv in iface_vars: calls += list(re.finditer(r'\b'+re.escape(iv)+r'\s*\.\s*\w+\s*\(',b,re.I))
            if calls:
                first=min(calls,key=lambda x:x.start());sw=self._state_write(b[first.end():])
                if sw and not re.search(r'\b(?:nonReentrant|lock(?:ed)?\s*=\s*true)\b',h+' '+b,re.I):
                    ev=b[max(0,first.start()-180):min(len(b),sw.start()+500)];fs += [self._finding('reentrancy','Reentrancy: external call precedes sensitive state update','critical',code,m.start(),'A callback-capable external call occurs before a sensitive state mutation, without an observed mutex. This is an attack-path hypothesis requiring local reproduction.',ev,.88),self._finding('callback','Cross-contract callback precedes state finalization','high',code,m.start(),'A non-view cross-contract call precedes sensitive accounting/state mutation; callback-controlled reentry should be tested locally.',ev,.84),self._finding('external_call','Security-sensitive cross-contract call ordering','high',code,m.start(),'A cross-contract call precedes a sensitive state mutation in the same function path.',ev,.78)]
                    break
        for m,n,a,h,b in funcs:
            if not re.search(r'\becrecover\s*\(',b,re.I): continue
            action=re.search(r'\b(?:claim|redeem|permit|execute|withdraw|approve|transfer|mint|release|settle)\w*\b',n,re.I) or self._state_write(b);fresh=re.search(r'\b(?:nonce|used|usedHash|usedDigest|deadline|expiry|chainId|domainSeparator|DOMAIN_SEPARATOR|EIP712)\b',b,re.I)
            if action and not fresh: fs += [self._finding('signature','Replayable signature authorization path','high',code,m.start(),'ecrecover authorizes a state-changing operation without an observed nonce, one-time digest consumption, expiry, or domain binding.',b,.86),self._finding('replay','Missing signature replay protection','high',code,m.start(),'A recovered signature appears reusable because no freshness/consumption control is visible before the mutation.',b,.84)]
        for m,n,a,h,b in funcs:
            init_name=bool(re.search(r'^(?:initialize|init|reinitialize|bootstrap|setup|configure|activate|boot)$',n,re.I));privileged=bool(re.search(r'\b(?:owner|admin|controller|governor|implementation|logic|upgrader|pendingOwner)\b\s*=',b,re.I));guard=bool(re.search(r'\b(?:initializer|reinitializer|onlyInitializing|_disableInitializers|once)\b',h+' '+b,re.I) or re.search(r'\b(?:initialized|ready|setupDone)\b\s*(?:==|!=)\s*(?:false|0)\b',b,re.I))
            if init_name and privileged and not guard:
                ev=b[:1800];fs += [self._finding('initialization','Unprotected initialization takeover','critical',code,m.start(),'An externally reachable initialization-style function establishes privileged state without an observed one-time guard.',ev,.92),self._finding('privilege','Initialization privilege escalation','critical',code,m.start(),'Initialization can establish privileged control without an observed one-time or authorization boundary.',ev,.9)]
                if re.search(r'\b(?:implementation|logic|upgrader)\b',b,re.I) or re.search(r'\b(?:upgrade|proxy|implementation)\b',code,re.I): fs.append(self._finding('upgrade','Initialization exposes upgrade privilege boundary','high',code,m.start(),'Initialization controls upgrade-relevant state without an observed guard.',ev,.87))
        for m,n,a,h,b in funcs:
            init_guarded=bool(re.search(r'^(?:initialize|init|reinitialize|bootstrap|setup|configure|activate|boot)$',n,re.I) and (re.search(r'\b(?:initializer|reinitializer|onlyInitializing|_disableInitializers|once)\b',h+' '+b,re.I) or re.search(r'\b(?:initialized|ready|setupDone)\b\s*(?:==|!=)\s*(?:false|0)\b',b,re.I) or re.search(r'\brequire\s*\([^;\n]{0,120}!\s*initialized\b',b,re.I)))
            privileged_write=bool(re.search(r'\b(?:owner|admin|controller|governor|chief|implementation|logic|upgrader)\b\s*=',b,re.I));sensitive=bool(re.search(r'\b(?:upgrade|setOwner|setAdmin|promote|rotate|mintCredit|mintShares|mintTokens|burnFrom|sweep|withdrawAll)\w*\b',n,re.I))
            if (privileged_write or sensitive) and not init_guarded and not self._auth(h,b):
                ev=b[:1700];fs += [self._finding('access_control','Sensitive privilege mutation lacks authorization','high',code,m.start(),'A privileged/value-bearing mutation is reachable without an observed authorization guard.',ev,.84),self._finding('privilege','Potential unauthorized privilege escalation','high',code,m.start(),'Caller control appears able to reach a privileged state mutation without an observed authorization invariant.',ev,.82)]
                if re.search(r'\b(?:implementation|logic|upgrade|delegatecall)\b',b,re.I): fs.append(self._finding('upgradeability','Unprotected upgradeability boundary','critical',code,m.start(),'Upgrade-relevant state can be changed without an observed privileged boundary.',ev,.88))
        for m,n,a,h,b in funcs:
            if not re.search(r'\b(?:state|status|phase|mode)\w*\s*=',b,re.I): continue
            guarded=bool(re.search(r'\brequire\s*\([^;\n]{0,260}\b(?:state|status|phase|mode|msg\.sender|owner|governor|admin)\b',b,re.I) or self._auth(h,b))
            if not guarded: fs.append(self._finding('state_machine','Unrestricted state-machine transition','high',code,m.start(),'A public state transition lacks an observed predecessor-state or authorization check, allowing callers to select a security-sensitive phase.',b,.82))
        for m,n,a,h,b in funcs:
            if not re.search(r'\b(?:getPrice|latestAnswer|latestRoundData|read|consult|spotPrice|twap)\s*\(',b,re.I): continue
            value_use=bool(re.search(r'\b(?:price|answer)\b[^;\n]{0,160}[*/]|[*/][^;\n]{0,160}\b(?:price|answer)\b',b,re.I));validated=bool(re.search(r'\b(?:updated|answered|round|stale|heartbeat|twap|timeWeighted)\b',b,re.I) and re.search(r'\brequire\s*\([^;\n]{0,260}\b(?:answer|updated|round|answered|stale)\b',b,re.I))
            if value_use and not validated: fs.append(self._finding('oracle_attack','Unchecked oracle input influences protocol value','critical',code,m.start(),'An externally sourced price influences a security-sensitive value calculation without an observed freshness, round-consistency, or sanity check.',b,.84))
        for m,n,a,h,b in funcs:
            for dm in re.finditer(r'\b\w+\s*=\s*([^;\n]*?/[^;\n]+)',b):
                expr=dm.group(1)
                if '*' not in expr.split('/')[0] and re.search(r'\b(?:amount|value|units|shares|rate|price)\b',expr,re.I): fs.append(self._finding('precision','Potential truncation before value scaling','medium',code,m.start()+dm.start(),'A value is divided before an observed compensating multiplication, creating a potential precision-loss surface that needs boundary-value reproduction.',expr,.76));break
            for tm in re.finditer(r'\b(?:transfer|send|call)\s*\([^;\n]*\b(?:payout|amount|units|shares)\b[^;\n]*\)',b,re.I):
                expr=tm.group(0);ratio=re.search(r'\b(?:payout|amount|units|shares)\b\s*\*\s*(\d+)\s*/\s*(\d+)',expr,re.I)
                if ratio and int(ratio.group(1))>int(ratio.group(2)): fs += [self._finding('asset_flow','Asset payout exceeds accounted unit','high',code,m.start(),'The transfer expression increases the requested unit by a fixed ratio while the caller balance is debited in the original unit.',b,.9),self._finding('accounting','Accounting conservation mismatch','high',code,m.start(),'Recorded units and transferred assets use different quantities on the withdrawal path.',b,.88)]
        for m in re.finditer(r'\bdelegatecall\s*\(',code,re.I):
            fn=None
            for fm,nn,aa,hh,bb in funcs:
                if fm.start()<=m.start()<=fm.end()+len(bb): fn=(hh,bb);break
            governed=self._auth(*(fn or ('','')));target_caller=bool(fn and re.search(r'\b(?:msg\.sender|next|target|implementation)\b[^;\n]{0,120}(?:delegatecall|=)',fn[1],re.I))
            if not governed or target_caller:
                fs.append(self._finding('delegatecall','Unsafe delegatecall / implementation trust boundary','high',code,m.start(),'A delegatecall creates an execution-context trust boundary and the reachable path is not visibly governed; local reproduction is required.',code[max(0,m.start()-260):m.end()+500],.8))
                if re.search(r'\b(?:implementation|logic|impl)\b',code,re.I): fs.append(self._finding('upgradeability','Unprotected delegatecall-backed upgradeability','critical',code,m.start(),'Delegatecall is paired with an implementation boundary that is not visibly protected in the reachable path.',code[max(0,m.start()-350):m.end()+600],.86))
        return fs

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
        if re.search(r'\b(?:onlyOwner|onlyAdmin|onlyRole|onlyGovernor|onlyController|hasRole|authorized|isOwner|_authorizeUpgrade|nonReentrant|gate|auth)\b',s,re.I): return True
        return bool(re.search(r'\brequire\s*\([^;\n]{0,260}\bmsg\.sender\b',s,re.I))
    def _init_guard(self,head,body):
        s=head+' '+body
        return bool(re.search(r'\b(?:initializer|reinitializer|onlyInitializing|_disableInitializers|once)\b',s,re.I) or re.search(r'\b(?:initialized|ready|setupDone)\b\s*(?:==|!=)\s*(?:false|0)\b',body,re.I) or re.search(r'\brequire\s*\([^;\n]{0,160}!\s*(?:initialized|ready|setupDone)\b',body,re.I))
    def _state_write(self,b):
        return re.search(r'\b(?:balance|balances|pending|shares|debt|state|status|phase|mode|owner|admin|controller|governor|implementation|logic|total|reserve|cash|credits|quota|nonce)\w*(?:\s*\[[^\]]+\])?\s*(?:=|\+=|-=|\*=|\+\+|--)',b,re.I)
    def analyze(self,code,name='target'):
        fs=[];funcs=self._functions(code);interfaces={};iface_vars={}
        for im in re.finditer(r'interface\s+(\w+)\s*\{(.*?)\}',code,re.I|re.S):
            interfaces[im.group(1)]={m.group(1) for m in re.finditer(r'function\s+(\w+)\s*\([^)]*\)\s*([^;]*);',im.group(2),re.I) if not re.search(r'\b(?:view|pure)\b',m.group(2),re.I)}
        for typ,var in re.findall(r'\b(\w+)\s+(?:public|private|internal)?\s*(\w+)\s*;',code):
            if typ in interfaces: iface_vars[var]=interfaces[typ]
        for m,n,a,h,b in funcs:
            calls=list(re.finditer(r'(?:address\s*\([^)]*\)|\w+)\s*\.\s*(?:call|send|transfer)\s*(?:\{|\()',b,re.I))
            for iv,methods in iface_vars.items():
                for cm in re.finditer(r'\b'+re.escape(iv)+r'\s*\.\s*(\w+)\s*\(',b,re.I):
                    if cm.group(1) in methods: calls.append(cm)
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
            init_name=bool(re.search(r'^(?:initialize|init|reinitialize|bootstrap|setup|configure|activate|boot)$',n,re.I));privileged=bool(re.search(r'\b(?:owner|admin|controller|governor|implementation|logic|upgrader|pendingOwner)\b\s*=',b,re.I));guard=self._init_guard(h,b)
            if init_name and privileged and not guard:
                ev=b[:1800];fs += [self._finding('initialization','Unprotected initialization takeover','critical',code,m.start(),'An externally reachable initialization-style function establishes privileged state without an observed one-time guard.',ev,.92),self._finding('privilege','Initialization privilege escalation','critical',code,m.start(),'Initialization can establish privileged control without an observed one-time or authorization boundary.',ev,.9)]
                if re.search(r'\b(?:implementation|logic|upgrader)\b',b,re.I) or re.search(r'\b(?:upgrade|proxy|implementation)\b',code,re.I): fs.append(self._finding('upgrade','Initialization exposes upgrade privilege boundary','high',code,m.start(),'Initialization controls upgrade-relevant state without an observed guard.',ev,.87))
        for m,n,a,h,b in funcs:
            init_guarded=bool(re.search(r'^(?:initialize|init|reinitialize|bootstrap|setup|configure|activate|boot)$',n,re.I) and self._init_guard(h,b));privileged_write=bool(re.search(r'\b(?:owner|admin|controller|governor|chief|implementation|logic|upgrader)\b\s*=',b,re.I));sensitive=bool(re.search(r'\b(?:upgrade|setOwner|setAdmin|setAuthority|setOracle|setValidator|setGuardian|promote|rotate|mintCredit|mintShares|mintTokens|burnFrom|sweep|withdrawAll)\w*\b',n,re.I))
            if (privileged_write or sensitive) and not init_guarded and not self._auth(h,b):
                ev=b[:1700];extra=' This mutation also crosses an upgrade boundary.' if re.search(r'\b(?:implementation|logic|upgrader)\b\s*=',b,re.I) or re.search(r'\b(?:implementation|logic)\b',code,re.I) else ''
                fs += [self._finding('access_control','Sensitive privilege mutation lacks authorization','high',code,m.start(),'A privileged/value-bearing mutation is reachable without an observed authorization guard.'+extra,ev,.84),self._finding('privilege','Potential unauthorized privilege escalation','high',code,m.start(),'Caller control appears able to reach a privileged state mutation without an observed authorization invariant.'+extra,ev,.82)]
        for m,n,a,h,b in funcs:
            if not re.search(r'\b(?:state|status|phase|mode)\w*\s*=',b,re.I): continue
            guarded=bool(re.search(r'\brequire\s*\([^;\n]{0,260}\b(?:state|status|phase|mode|msg\.sender|owner|governor|admin)\b',b,re.I) or self._auth(h,b))
            if not guarded:
                pos=m.start()+max(0,b.find('state') if 'state' in b else b.find('phase'));fs += [self._finding('state_machine','Unrestricted state-machine transition','high',code,m.start(),'A public state transition lacks an observed predecessor-state or authorization check, allowing callers to select a security-sensitive phase; this is also a business logic invariant failure.',b,.82),self._finding('business_logic','Business logic invariant failure','high',code,pos,'A business logic invariant is missing from a security-sensitive state transition; the caller can move the protocol into a new phase without proving the required authorization or predecessor state.',b,.78)]
        for m,n,a,h,b in funcs:
            oracle_call=re.search(r'\b(?:getPrice|latestAnswer|latestRoundData|read|consult|spotPrice|twap)\s*\(',b,re.I)
            if not oracle_call: continue
            assigned=re.search(r'\b(?:uint\w*\s+)?(\w+)\s*=\s*\w+\.(?:getPrice|latestAnswer|read|spotPrice|twap)\s*\(',b,re.I)
            value_use=bool(re.search(r'\b(?:price|answer)\b[^;\n]{0,160}[*/]|[*/][^;\n]{0,160}\b(?:price|answer)\b',b,re.I) or (assigned and re.search(r'\b'+re.escape(assigned.group(1))+r'\b[\s\S]{0,400}[*/]',b,re.I)))
            validated=bool(re.search(r'\b(?:updated|answered|round|stale|heartbeat|twap|timeWeighted)\b',b,re.I) and re.search(r'\brequire\s*\([^;\n]{0,260}\b(?:answer|updated|round|answered|stale)\b',b,re.I))
            if value_use and not validated: fs.append(self._finding('oracle_attack','Unchecked oracle input influences protocol value','critical',code,m.start(),'An externally sourced price influences a security-sensitive value calculation without an observed freshness, round-consistency, or sanity check.',b,.84))
        for m,n,a,h,b in funcs:
            for dm in re.finditer(r'\b(\w+)\s*=\s*([^;\n]*?/[^;\n]+)',b,re.I):
                expr=dm.group(2)
                if '*' not in expr.split('/')[0] and re.search(r'\b(?:amount|value|units|shares|rate|price)\b',expr,re.I): fs.append(self._finding('precision','Potential truncation before value scaling','medium',code,m.start(),'A value is divided before an observed compensating multiplication, creating a potential precision-loss surface that needs boundary-value reproduction.',expr,.76));break
            for cm in re.finditer(r'\b[\w\[\].]+\s*(?:\+=|-=)\s*[^;\n]*/\s*\d+',b,re.I):
                fs.append(self._finding('precision','Precision loss in compound value conversion','medium',code,m.start()+cm.start(),'A value-bearing compound assignment performs integer division directly, creating truncation risk that should be reproduced at boundary values.',cm.group(0),.8));break
            ratio_assign=re.search(r'\b(?:uint\w*\s+)?(payout|out|payment|amountOut)\s*=\s*\w+\s*\*\s*(\d+)\s*/\s*(\d+)\s*;',b,re.I)
            if ratio_assign and int(ratio_assign.group(2))>int(ratio_assign.group(3)) and re.search(r'\b(?:transfer|send|call)\s*\([^;\n]*\b'+re.escape(ratio_assign.group(1))+r'\b',b,re.I):
                fs += [self._finding('asset_flow','Asset payout exceeds accounted unit','high',code,m.start(),'The withdrawal path transfers a scaled-up payout while the caller balance is debited in the original unit.',b,.9),self._finding('accounting','Accounting conservation mismatch','high',code,m.start(),'Recorded units and transferred assets use different quantities on the withdrawal path.',b,.88)]
            transfers=list(re.finditer(r'(?:\b\w+\s*\([^)]*\)|\w+)\s*\.\s*(?:transfer|send)\s*\(\s*(\w+)\s*\)',b,re.I))
            for tm in transfers:
                pay=tm.group(1)
                for sm in re.finditer(r'\b(\w+)\s*-\=\s*([^;]+);',b,re.I):
                    expr=re.sub(r'\s+','',sm.group(2))
                    if expr and expr!=pay:
                        fs.append(self._finding('accounting','State debit differs from transferred amount','high',code,m.start(),'A recorded balance/reserve debit differs from the amount actually transferred on the same path.',b,.86));break
        for m in re.finditer(r'\bdelegatecall\s*\(',code,re.I):
            fn=None
            for fm,nn,aa,hh,bb in funcs:
                if fm.start()<=m.start()<=fm.end()+len(bb): fn=(hh,bb);break
            governed=self._auth(*(fn or ('','')))
            if not governed:
                ev=code[max(0,m.start()-350):m.end()+650];fs += [self._finding('delegatecall','Unsafe delegatecall / implementation trust boundary','high',code,m.start(),'A delegatecall creates an execution-context trust boundary and the reachable path is not visibly governed; this is an upgradeability boundary requiring local reproduction.',ev,.8),self._finding('upgradeability','Unprotected delegatecall-backed upgradeability','critical',code,m.start(),'A delegatecall path is not visibly governed, so implementation control can cross the proxy boundary without an observed privileged check.',ev,.86)]
        return fs
'''
| "An access control scheme with fine-grained time constrained attributes based on smart contract and trapdoor"
| Available from: https://ieeexplore.ieee.org/abstract/document/8798859
| Published in: 2019 26th International Conference on Telecommunications (ICT) 
| Notes: each attribute has a trapdoor
| Security Assumption: 
|
| type:           ciphertext-policy attribute-based encryption (public key)
| setting:        Pairing
| 

:Authors:    Qin
'''


from __future__ import print_function
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output
from charm.core.math.pairing import hashPair as extractor


# type annotations
pk_t = { 'g':G1, 'g2':G2, 'h':G1, 'f':G1, 'e_gg_alpha':GT }
mk_t = {'beta':ZR, 'g2_alpha':G2 }
sk_t = { 'D':G2, 'Dj':G2, 'Djp':G1, 'S':unicode } 
ct_t = { 'C_tilde':GT, 'C':G1, 'Cy':G1, 'Cyp':G2, 'policy':unicode, 'attributes':unicode }

debug = False
class TrapAC(ABEnc):
      
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)
        group = groupObj

    @Output(pk_t, mk_t)    
    def setup(self):
        g, gp = group.random(G1), group.random(G2)
        alpha, beta, gamma = group.random(ZR), group.random(ZR), group.random(ZR)
        # initialize pre-processing for generators
        g.initPP(); gp.initPP()
        
        h = g ** beta; f = g ** ~beta; m =g ** gamma
        e_gg_alpha = pair(g, gp ** alpha)

        pk = { 'g':g, 'g2':gp, 'h':h, 'f':f, 'm':m, 'e_gg_alpha':e_gg_alpha }
        mk = {'beta':beta, 'gamma':gamma, 'g2_alpha':gp ** alpha }
        return (pk, mk)
    
    @Input(pk_t, mk_t, [str])
    @Output(sk_t)
    def keygen(self, pk, mk, S):
        r = group.random() 
        g_r = (pk['g2'] ** r)    
        D = (mk['g2_alpha'] * g_r) ** (1 / mk['beta'])        
        D_j, D_j_pr = {}, {}
        for j in S:
            r_j = group.random()
            D_j[j] = g_r * (group.hash(unicode(j), G2) ** r_j)
            D_j_pr[j] = pk['g'] ** r_j
        S = [unicode(s) for s in S]

	TK = pk['m'] ** (1 / mk['beta'])

        return { 'D':D, 'Dj':D_j, 'Djp':D_j_pr, 'S':S,'TK':TK  }
    
    @Input(pk_t, GT, str)
    @Output(ct_t)
    def encrypt(self, pk, M, policy_str): 
        policy = util.createPolicy(policy_str)
        a_list = util.getAttributeList(policy)
        s = group.random(ZR)
	#st =  group.random(ZR)
        #print('s_t=>',st)
        shares = util.calculateSharesDict(s, policy)      

        C = pk['h'] ** s
        C_y, C_y_pr = {}, {}
	A_y, B_y = {},{}

        for i in shares.keys():
	    
            j = util.strip_index(i)
	    r_t = group.random(ZR) 
	    s_t =  group.random(ZR)

            C_y[i] = pk['g'] ** (shares[i]*s_t)
            C_y_pr[i] = group.hash(j, G2) ** (shares[i] *s_t)

	    A_y[i] = pk['g'] ** r_t   #
            B_y[i] = s_t + group.hash(extractor(pair(pk['m'],pk['f'])**r_t),ZR) 


        return { 'C_tilde':(pk['e_gg_alpha'] ** s) * M,
                 'C':C, 'Cy':C_y, 'Cyp':C_y_pr,'Ay':A_y,'By':B_y, 'policy':unicode(policy_str), 'attributes':a_list }
 
    #@Input(pk_t, sk_t, ct_t)
    #@Output(ct_t)
    def proxy_decrypt(self, pk, sk, ct,valid_attr):
       
        policy = util.createPolicy(ct['policy'])
        pruned_list = util.prune(policy, valid_attr)
        if pruned_list == False:
            return False
        z = util.getCoefficients(policy)
        A = 1 
	print (pruned_list)
        for i in pruned_list:
            j = i.getAttributeAndIndex(); k = i.getAttribute()

 	    s_t =ct['By'][j]-group.hash(extractor(pair(sk['TK'], ct['Ay'][j])),ZR) #

            A *= ( pair(ct['Cy'][j], sk['Dj'][k]) / pair(sk['Djp'][k], ct['Cyp'][j]) ) ** (z[j]/s_t)

        return {'C_tilde':ct['C_tilde'],'C':ct['C'],'FR':A}


    #@Input(pk_t, sk_t, ct_t)
    #@Output(GT)
    def decrypt(self, pk, sk, ct):

         return ct['C_tilde'] / (pair(ct['C'], sk['D']) / ct['FR'])   


def main():   
    groupObj = PairingGroup('SS512')

    cpabe = TrapAC(groupObj)
    attrs = ['ONE', 'TWO', 'THREE']
    access_policy = '((four AND two) OR (three AND one))'
    valid_attr = ['ONE','THREE']   # attribute in period time
    if debug:
        print("Attributes =>", attrs); print("Policy =>", access_policy)

    (pk, mk) = cpabe.setup()

    sk = cpabe.keygen(pk, mk, attrs)
   # print("sk :=>", sk)

    rand_msg = groupObj.random(GT)
    if debug: print("msg =>", rand_msg)
    ct = cpabe.encrypt(pk, rand_msg, access_policy)
    if debug: print("\n\nCiphertext...\n")
    groupObj.debug(ct)
    rect = cpabe.proxy_decrypt(pk, sk, ct,valid_attr)
    if debug: print("\n\nproxy_decrypt...\n")

    rec_msg = cpabe.decrypt(pk, sk, rect)
    if debug: print("\n\nDecrypt...\n")
    if debug: print("Rec msg =>", rec_msg)

    assert rand_msg == rec_msg, "FAILED Decryption: message is incorrect"
    if debug:print("Successful Decryption!!!")

if __name__ == "__main__":
    debug = True
    #main()
   

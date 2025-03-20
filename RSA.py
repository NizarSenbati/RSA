##implementation de rsa
import time
import random
import math

class RSA():

    def __init__(self, p: int = None, q: int = None, n: int = None, phi: int = None, e: int = None, d: int = None):
        self.p = p
        self.q = q
        self.n = n
        self.phi = phi
        self.e = e
        self.d = d
        self.taille_bloc = 0

    def euclide_pgcd(self, a, b):
        if(b == 0):
            return a
        return self.euclide_pgcd(b, a%b)

    def euclide_etendu(self, a, b):
        uii, ui = 1, 0
        vii, vi = 0, 1
        rii = a if a > b else b
        ri = b if a > b else a
        r = a#arbitraire
        q = rii // ri

        while( r != 0 ):
            q = rii // ri
            print(f"q = {rii} // {ri} = {q}")
            u = uii - q * ui
            print(f"u: {u} = {uii} - {q} * {ui}")
            v = vii - q * vi
            print(f"v: {v} = {vii} - {q} * {vi}")
            r = a*u + b*v
            print(f"r: {r} = {a} * {u} + {b} * {v}")
            uii, ui = ui, u
            vii, vi = vi, v
            rii, ri = ri, r
            # time.sleep(3)
            print("-------------------------------------------------")
            if r == 1:
                print(f"{ui} * {a} + {vi} * {b} = 1")
                return (ui, vi)
        else:
            print("erreur lors du calcul d'euclide étendu!")
            return -1

    def tobin(self, nbr):
        return [int(i) for i in bin(nbr)[2:]]

    def pow_rec(self, nbr, exp, mod):
        if(exp == 1 or exp == 0):
            return nbr%mod
        return (self.pow_rec(nbr, exp/2, mod) **2) % mod

    def calcule_efficace(self, nbr, exp, base):
        valeurs = [nbr % base]
        puiss_bin = self.tobin(exp)
        puiss_bin.reverse()
        resultat = 1
        for i in range(len(puiss_bin)):
            if i > 0:
                val = (valeurs[i-1] ** 2) % base
                valeurs.append(val)
            if puiss_bin[i] == 1:
                resultat *= valeurs[i]
                resultat = resultat % base
        return resultat

    def private_key(self):
        result = self.euclide_etendu(self.phi, self.e)
        if result == -1:
            print("Erreur lors du calcul de la clé privée!")
            return
        (_, self.d) = result
        if(self.d < 0):
            self.d = self.d + self.phi
        print(f"clé privée: {self.d}")
        test = self.calcule_efficace(self.d * self.e, 1, self.phi)
        test2 = pow(self.d * self.e, 1, self.phi)
        print("pow({d} * {e}, 1, {phi}) = {test2}".format(d=self.d, e=self.e, phi=self.phi, test2=test2))
        print(f"test2: {test2}, test1: {test}")
        if test == 1:
            print("clé privée testée!")
        else:
            print("clé privée incorrecte!")
        print("-------------------------------------------------")

    def valeurs(self):
        self.p = input("entrez p: ")
        self.q = input("entrez q: ")
        # self.p = 7
        # self.q = 11
        # self.e = 17
        self.n = int(self.p) * int(self.q)
        self.phi = (int(self.p)-1) * (int(self.q)-1)
        check = True
        while (check):
            e = random.randint(15, int(self.phi))
            if(self.euclide_pgcd(int(self.phi), int(e)) == 1):
                self.e = e
                print(f"e: {self.e}")
                check = False
            
        self.private_key()

    def decouper(self, texte):
        self.taille_bloc = int(math.log2(self.n))//8
        # print(f"taille: {taille_bloc}, nbrbits: {int(math.log2(self.n))}")
        if(self.taille_bloc < 1):
            print("taille trop petite, chiffrement impossible! Pensez a choisir p et q plus grands!")
            exit(-1)
        blocs = []
        for i in range(0, len(texte), self.taille_bloc):
            blocs.append(texte[i:i + self.taille_bloc])
        for bloc in blocs:
            while len(bloc) < self.taille_bloc:
                bloc.append(0)
        return blocs
    
        #passage vers la base 10

    def base256_base10(self, blocs):
        message = []
        for bloc in blocs:
            m = 0
            for i in range(0, len(bloc)):
                m += 256**i * int(bloc[i])
            message.append(m)
        return message

    def chiffrement(self, text):
        ascii_text = [ord(i) for i in text]
        print("1---ascii              : ", ascii_text)
        blocs = self.decouper(ascii_text)
        print("2---blocs ascii        : ", blocs)
        mi = self.base256_base10(blocs)
        print("3---message en base 10 : ", mi)
        ci = [self.calcule_efficace(m, self.e, self.n) for m in mi]
        print("4---cypher             : ",ci)
        return ci
    
    def base10_to_base256(self, bloc):
        message = []
        for number in bloc:
            result = []
            while number > 0:
                result.append(number % 256)
                number //= 256
            while len(result) < self.taille_bloc:
                result.append(0)
            message.append(result)#(result[::-1])
        return message

    def decrypt_rsa(self, encrypted_blocs):
        mi = [self.calcule_efficace(c, self.d, self.n) for c in encrypted_blocs]
        print("3---cypher decrypté    : ", mi)
        blocs = self.base10_to_base256(mi)
        print("2---message en base 256: ", blocs)
        ascii_text = []
        for bloc in blocs:
            for i in bloc:
                ascii_text.append(chr(i))
        
        print("1---texte recouvert: ", ascii_text)
        texte = ''.join(ascii_text)
        print("|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||")
        print("message original: ", texte)
        return ascii_text


def main():
    rsa = RSA()
    rsa.valeurs()
    print("entrez du texte a chiffrer: ")
    texte = input()
    cypher = rsa.chiffrement(texte)
    texte_recov = rsa.decrypt_rsa(cypher)

if __name__ == "__main__":
    main()

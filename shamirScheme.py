from __future__ import division
import random
import functools
from timeit import timeit
from Crypto.Util.number import bytes_to_long, long_to_bytes
import ast 
import gmpy2


# (per questa applicazione vogliamo un numero PRIME noto).
# il più vicino possibile al nostro livello di sicurezza; 
# ad es. con il livello di sicurezza desiderato di 128 bit: 
# utilizziamo il 12-esimo PRIME di Mersenne
# Se prendessimo un PRIME troppo grande, tutto il testo cifrato sarebbe troppo grande.
# Se lo prendessimo troppo piccolo, invece, la sicurezza sarebbe compromessa)

PRIME = 2**521 - 1 # 13-esimo PRIME di Marsenne


interorandom = functools.partial(random.SystemRandom().randint, 0)
prod = lambda x, y: x * y


def eval_at(poly, x, prime):
	'''
	Calcola il polinomio in x
	'''
	# print(poly)
	accum = 0
	for coeff in reversed(poly):
		accum *= x
		accum += coeff
		accum %= prime
	return accum


def create_shares_from_secret(secret, minimum, nShares, prime=PRIME):
	'''
	Divide il segreto in "nShares" shares, con un threshold 
	di "minimum" shares necessari per recuperare il segreto iniziale
	'''
	# poly = [secret]
	# print(poly)
	if minimum > nShares:
		raise ValueError("Il segreto sarebbe irrecuperabile se dovessero servire più shares di quanti ne esistano effettivamente.")
	poly = [secret] + [interorandom(prime) for i in range(minimum-1)]
	# poly = [secret] + poly
	points = [(i, eval_at(poly, i, prime)) for i in range(1, nShares + 1)]
	# print(poly[0], points)
	return points


def extended_gcd(a, b):
	x = 0
	last_x = 1
	y = 1
	last_y = 0
	while b != 0:
		quot = a // b
		a, b = b,  a%b
		x, last_x = last_x - quot * x, x
		y, last_y = last_y - quot * y, y
	return last_x, last_y


def divmod(num, den, p):
	'''
	Calcola num / den modulo p numero PRIME, cioè
	ritorno il valore tale che renda vera la seguente uguaglianza:
	den * divmod(num, den, p) % p == num
	'''
	inv, _ = extended_gcd(den, p)
	return num * inv


def lagrange_interpolation(x, x_s, y_s, p):
	'''
	Trovare il valore di y per la data x, dati n punti composti dalla coppia (x, y); 
	k punti serviranno a definire un polinomio fino al k-esimo ordine
	'''
	k = len(x_s)
	assert k == len(set(x_s)), "I punti devono essere distinti"
	PI = lambda vals: functools.reduce(prod, vals, 1) # PI -- Prodotto elementi di una lista
	# def PI(vals): return functools.reduce(prod, vals, 1)
	nums = []  # per evitare divisioni non precise
	dens = []
	for i in range(k):
		others = list(x_s)
		cur = others.pop(i)
		nums.append(PI(x - o for o in others))
		dens.append(PI(cur - o for o in others))
	den = PI(dens)
	num = sum([divmod(nums[i] * den * y_s[i] % p, dens[i], p) 
				for i in range(k)])
	return (divmod(num, den, p) + p) % p


def recover_secret(shares, prime=PRIME):
	'''
	Recupera il segreto dalle coppie di punti (x, y) giacenti sul polinomio
	'''
	if len(shares) < 2:
		raise ValueError("Sono necessari almeno due shares");
	x_s, y_s = zip(*shares);
	return lagrange_interpolation(0, x_s, y_s, prime);


def main():
	b = input("Cosa vuoi fare? [E]ncrypt, [D]ecrypt:\n")
	if b.lower() == "e":
		secretString  = input("Inserire il segreto: ");
		secret = bytes_to_long(secretString.encode());
		# print(secret)
		nShares = int(input("Inserire il numero di shares che si vogliono: "));
		minimum = int(input("Inserire il numero minimo di shares per recuperare il segreto (almeno 2): "));
		shares  = create_shares_from_secret(secret, minimum, nShares);
		time = timeit(lambda: create_shares_from_secret(secret, minimum, nShares), number=1);
		print(shares);
		print(f"Tempo totale per crittare: {time}")
		print(recover_secret(random.sample(shares, minimum)));
		assert recover_secret(random.sample(shares, minimum)) == secret, "No";
		assert recover_secret(shares) == secret, "Nope";
	elif b.lower() == "d":
		inpShares = input("Inserire una lista di almeno 'minimum' shares da decrittare:\n");
		shares = ast.literal_eval(inpShares);
		print("Se ciò che hai inserito è corretto, il plaintext è: ");
		try:
			print(long_to_bytes(recover_secret(shares)).decode());
		except:
			print("Servono più shares per ricostruire il segreto!");
		

if __name__== "__main__":
	main()




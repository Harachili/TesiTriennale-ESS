from __future__ import division
import random
import functools
from timeit import timeit
from Crypto.Util.number import bytes_to_long, long_to_bytes
import ast 


# (per questa applicazione vogliamo un numero PRIME noto).
# il più vicino possibile al nostro livello di sicurezza; 
# ad es. con il livello di sicurezza desiderato di 128 bit: 
# utilizziamo il 12-esimo PRIME di Mersenne
# Se prendessimo un PRIME troppo grande, tutto il testo cifrato sarebbe troppo grande.
# Se lo prendessimo troppo piccolo, invece, la sicurezza sarebbe compromessa)

PRIME = 2**521 - 1 # 13-esimo PRIME di Marsenne

# Il 12-esimo PRIME di Mersenne è 2**127 - 1

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


def create_poly(secret, minimum):
	print(secret)
	return [secret] + [interorandom(PRIME) for i in range(minimum-1)]


def create_shares_from_secret(poly, nShares, prime=PRIME):
	'''
	Divide il segreto in "nShares" shares, con un threshold 
	di "minimum" shares necessari per recuperare il segreto iniziale
	'''
	# poly = [secret]
	# print(poly)
	# if minimum > nShares:
	# 	raise ValueError("Il segreto sarebbe irrecuperabile se dovessero servire più shares di quanti ne esistano effettivamente.")
	
	# poly = [secret] + poly
	points = [(i, eval_at(poly, i, prime)) for i in range(1, nShares + 1)]
	# print(poly[0], points)
	return points


def extended_gcd(a, b):
	'''
	divisione di interi modulo p, significa trovare l'inverso del denominatore
	modulo p e poi moltiplicare il numeratore per il suo inverso
	ad esempio: l'inverso di A è quel B tale che A*B % p == 1
	Per calcolarlo utilizzo l'algoritmo esteso di Euclide
	http://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Computation
	'''
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
	totTime = 0;
	d = dict();
	counter = 1
	toInsToDecr = []
	b = input("Cosa vuoi fare? [E]ncrypt, [D]ecrypt:\n")
	if b.lower() == "e":
		secretString  = input("Inserire il segreto da crittare: ");
		secret = bytes_to_long(secretString.encode());
		minimum = int(input("Inserire qui la soglia minima di shares di cui si deve avere bisogno per ricostruire il segreto: "));
		poly = create_poly(secret, minimum);
		while True:
			print(f"Benvenuto partecipante n. {counter}");
			point = create_shares_from_secret(poly, counter)[-1];
			time = timeit(lambda: create_shares_from_secret(poly, counter)[-1], number=1);
			print(f"Lo share per il partecipante n. {counter} è: {point}");
			print(f"Il tempo impiegato per creare lo share, in microsecondi, è: {time}");
			totTime+=time;
			d[point[0]] = point[1];
			counter += 1;
			ans = input("Desideri ricevere un altro share? [Y]|[N]\n");

			if ans.lower() == "n":
				if counter < minimum: raise ValueError("Non hai richiesto abbastanza shares, il segreto è perso per sempre!")
				for i in range(1, counter):
					toInsToDecr.append((i, d[i]))
				break;
		print(toInsToDecr)
		print(f"Tempo totale impiegato nel crittare: {totTime}") # 150 encryptions, con soglia 15: 0.16363659693161026 secondi

	elif b.lower() == "d":
		inpShares = input("Inserire una lista con un numero di elementi almeno pari al numero minimo di shares necessari per decrittare:\n");
		shares = ast.literal_eval(inpShares);
		try:
			print("Se ciò che hai inserito è corretto, il plaintext è: ");
			print(long_to_bytes(recover_secret(shares)).decode());
		except UnicodeDecodeError:
			print("Non hai inserito abbastanza shares per ricostruire il segreto!")

if __name__== "__main__":
	main()






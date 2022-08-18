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

PRIME = 2**127 - 1 # 12-esimo PRIME di Marsenne

# Il 13-esimo PRIME di Mersenne è 2**521 - 1

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

"""
def make_random_shares(minimum, shares, prime=PRIME):
	'''
	Genera dei punti dal segreto tali che ne bastino "minimum" su "shares"
	per ricreare effettivamente il segreto
	'''
	if minimum > shares:
		raise ValueError("pool secret would be irrecoverable")
	poly = [interorandom(prime) for i in range(minimum)]
	points = [(i, eval_at(poly, i, prime))
			  for i in range(1, shares + 1)]
	# print(poly[0], points)
	return poly[0], points
"""

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

# divisione di interi modulo p, significa trovare l'inverso del denominatore
# modulo p e poi moltiplicare il numeratore per il suo inverso
# ad esempio: l'inverso di A è quel B tale che A*B % p == 1
# Per calcolarlo utilizzo l'algoritmo esteso di Euclide
# http://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Computation
# Per l'implementazione mi sono ispirato a https://github.com/lapets/egcd/blob/main/egcd/egcd.py
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

"""
def test():
	'Esegue l'operazione di codifica + decodifica più volte e ritorna il tempo in microsecondi'
	for i in range(2, 20):
		for j in range(i, i * 2):
			secret, shares = make_random_shares(i, j)
			print("secret: ", secret,"\nshares: ", shares)
			assert recover_secret(random.sample(shares, i)) == secret # Prendi tra tutti gli shares, 'i' valori differenti; se la funzione recover_secret ritorna il segreto tutto ok
			assert recover_secret(shares) == secret
	return timeit.timeit(
		lambda: recover_secret(make_random_shares(4, 8)[1]),
		number=1000) * 1000
# print(test())
"""

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

"""
SECRET SHARING:
Cosa vuoi fare? [E]ncrypt, [D]ecrypt:
e
Inserire il segreto: c
Inserire il numero di shares che si vogliono: 8
Inserire il numero minimo di shares per recuperare il segreto (almeno 2): 3
[(1, 42746481739456477798660845194980202545), (2, 120361495285456260365755132684708452895), (3, 62703857177530115969595558753300645422), (4, 39914750876147276341869427116640885853), (5, 51994176381307741482576737774729174188), (6, 98942133693011511391717490727565510427), (7, 10617439350789354337604382259265788843), (8, 127302460275579733783612019801598220890)]
Tempo totale per crittare: 0.0001356089996988885
99

EVOLVING SECRET SHARING:
Cosa vuoi fare? [E]ncrypt, [D]ecrypt:
e
Inserire il segreto da crittare: c
Inserire qui la soglia minima di shares di cui si deve avere bisogno per ricostruire il segreto: 3
99
[(1, 27267228364820182363130257192757543927), (2, 9721928639967139460579431490616422765), (3, 117505284285910103024034826609460742340), (4, 10334928381710609590121835117522291198), (5, 28493227848307122622215064446569280793), (6, 1838999225230410388627210880717605398), (7, 100513425972949704621045578135851370740), (8, 154375324630995773587782862496086471092)]
Tempo totale impiegato nel crittare: 0.0003544329956639558



SECRET SHARING:
Cosa vuoi fare? [E]ncrypt, [D]ecrypt:
e
Inserire il segreto: ciaociao
Inserire il numero di shares che si vogliono: 10
Inserire il numero minimo di shares per recuperare il segreto (almeno 2): 4
[(1, 106528726991999212185843262138413262714), (2, 24124533741556585159393289810793327729), (3, 151258234423080131498640506030305131823), (4, 35694725908631705115975451417346483860), (5, 75904822372619318582225185171735721339), (6, 159935787608043289273154855345638864578), (7, 5693701947434702832842306275337828168), (8, 11649379565201571832114597160650949608), (9, 65850084254344213646736876053744249216), (10, 56343079807862945652474291006783747310)]
Tempo totale impiegato nel crittare: 0.0001572479959577322
7163363813346599279

EVOLVING SECRET SHARING:
Cosa vuoi fare? [E]ncrypt, [D]ecrypt:
e
Inserire il segreto da crittare: ciaociao
Inserire qui la soglia minima di shares di cui si deve avere bisogno per ricostruire il segreto: 4
7163363813346599279
Benvenuto partecipante n. 1
[(1, 25857941577887849072560513548191720356), (2, 39976884492641255123248884909678023766), (3, 20463898687438419899270226857557913476), (4, 115567237565926776872353592067467899180), (5, 133252787610815296050853425783276279118), (6, 51627618765282179174811476964735457257), (7, 18939984432974859715956798287481943291), (8, 13296954557071539414331138711268141187), (9, 12805599080750420009976247195846454912), (10, 165714171407658934974621176416853394160)]
Tempo totale impiegato nel crittare: 0.00043553501745918766



SECRET SHARING:
Cosa vuoi fare? [E]ncrypt, [D]ecrypt:
e
Inserire il segreto: ciaociaociaociao
Inserire il numero di shares che si vogliono: 23
Inserire il numero minimo di shares per recuperare il segreto (almeno 2): 13
[(1, 103102721416546389377747146219686257251), (2, 145967088045743671639434887192136531820), (3, 26794760535016936313347271409035125920), (4, 12946907212578242231029717893134714757), (5, 71039981404424539366278418708699476444), (6, 69673423476684813866892580865791511014), (7, 34706848085563777022543279051552531567), (8, 7653567996131617867210599306588494249), (9, 705629437114798391552415361586581377), (10, 48533514271770930657489464742726649046), (11, 58402179409321471607308252298502079599), (12, 97188585999170360160470339142212810256), (13, 109305161584964809125167361257259467542), (14, 115942574910346324485183709825510519831), (15, 81636192614982844721048657028254339732), (16, 62167053294629861638486814672566171598), (17, 98952931862603410078099653939450381998), (18, 112666000706658226964561069511140216840), (19, 129764324441528786911177006576797333458), (20, 93881760784055673184108526032577132711), (21, 27821441331408438887490503569912356546), (22, 108368516325208249833834276195514135286), (23, 102003965938671088553714769553477608477)]
Tempo totale per crittare: 0.00079077100235736
132140738971676834921518689066865484143

EVOLVING SECRET SHARING:
Cosa vuoi fare? [E]ncrypt, [D]ecrypt:
e
Inserire il segreto da crittare: ciaociaociaociao
Inserire qui la soglia minima di shares di cui si deve avere bisogno per ricostruire il segreto: 13
132140738971676834921518689066865484143
[(1, 26303488633323602800969497413341269457), (2, 58783655402265274377216322478476347889), (3, 95793264604743726911496051349961258115), (4, 68654556725302861721873133590305175015), (5, 142878784586686841525010441747036507401), (6, 55623077562140331373420316166859764451), (7, 66876955846857964694292097569374367436), (8, 71047360657665509921499741931451182717), (9, 99398579126742207669759589656022022153), (10, 109233414022852855153711035112797821331), (11, 56819800263628074773934002181272420659), (12, 41599462662532373647255459296322498369), (13, 64818698906343544993717024325672027724), (14, 4675080313420012279391797210541705040), (15, 54584932420287862635447325639656001571), (16, 121932723928020326433290243648506540111), (17, 53691958725117223748886097910954654044), (18, 65819569486340992269247951167026575429), (19, 19401955861589968521784785694906916040), (20, 113528866240654800744413496426701940840), (21, 109015055108047522475252010669829162069), (22, 98140626980320004518310274596933709320), (23, 21364252733837303301520316954044150836)]
Tempo totale impiegato nel crittare: 0.004249283017998096



"""




parsed_uri(URIString, URI) :-
	%prima trasformazione
	string_to_list(URIString, ListedCharCodes),

	%seconda trasformazione
	codeListToCharList(ListedCharCodes, LChars),
	
	%ci basta un solo ':', ma ci deve essere!
	member(':', LChars),
	!,	

	%riconoscimento dello scheme
	crack_string(LChars, LChars, :, Scheme, Substring0),

	%riposizionamento del ':', necessario al riconoscimento
	%dell' authority (vedi sotto)
	append([':'], Substring0, Substring1),

	
	%ora ci concentriamo sull' authority: con la prima chiamata
	%verifichiamo che sia presente (se e' presente deve esistere
	%il prefisso '://', vedi sotto)
	verify_authority(Substring1, AuthorityPresence),

	
	%con questo passo ci posizioniamo opportunamente nella lista,
	%a seconda della presenza o meno dell' authority
	decide_authority(Substring1, AuthorityPresence, Next1),

	%il fragment e' identificato da # ed il char non puo' essere
	%altrove nell' uri. Ad ogni predicato del genere associamo
	%un valore booleano, poiche' se, ad esempio, troviamo '#' 
	%allora il fragment ci deve essere, non vuoto (altrimenti non
	%avrebbe dovuto esserci '#').
	%Fa eccezione la path (vedi sotto).
	%Ad ogni parte associamo un valore booleano di presenza, o di
	%natura come nel caso della path
	verify_fragment(Next1, Next2, Fragment, BooleanFrag),

	%il discorso e' analogo per '?', che si puo' trovare al piu'
	%nel fragment, che abbiamo gia' sistemato via
	verify_query(Next2, Next3, Query, BooleanQuery),

	%ora nella stringa e' rimasto o solo il path, nel caso in cui
	%l' host non ci sia, oppure l' authority ed il path, nel caso
	%in cui lo scheme sia uno dei noti quattro: allora per 
	%individuare il path abbiamo bisogno di conoscere la 
	%situazione (vedi sotto) e vogliamo anche sapere se, 
	%essendoci l' auth, potremmo essere in presenza di un path-
	%after-authority
	define_path(Next3, Next4, Path, AuthorityPresence, BoolPAA),



	%ora in Substring3 ragionevolmente c'e' rimasto l' authority,
	%se presente, altrimenti abbiamo una lista vuota; se c'e' lo
	%dobbiamo investigare per dividerlo in userinfo, host,
	%port; partiamo ancora dal fondo della stringa, poi torniamo
	%all' inizio per l' user

	verify_port(
		Next4, 
		Next5, 
		Port, 
		AuthorityPresence,
		BooleanPort),

	verify_userinfo(
		Next5, 
		Next6, 
		Userinfo,
		AuthorityPresence, 
		BooleanU),

	%ora Next6 contiene solo l' host! Possiamo passare alla 
	%verifica delle singole parti, infatti sinora le abbiamo solo
	%individuate ma non sappiamo se abbiano contenuti corretti o
	%meno
	
	%lo scheme ci *deve* essere! Ho notato che per scheme vuoti
	%la struttura viene ad esser la prima se manca ':', la
	%seconda se c'e': ovviamente ':' ci deve essere (gestito su)
	Scheme \= ['[', ']'],
	Scheme \= [],

	%per come ho man mano suddiviso la stringa, il caso base di
	%uri minimo e' riconosciuto come avere l' authority uguale
	%allo scheme
	set_proper(Scheme, Next6, NewAuthHost),


	%ora abbiamo finito di associare alle componenti dell' uri	%le parti presenti nella stringa uri data; resta pero' da
	%vedere se siano composte di caratteri leciti, e se sia 
	%lecita la loro stessa presenza (ad esempio, non puo' esserci
	%un userinfo senza hostname, o se vi e' un '?' nella 
	%sottostringa prima della parte fragment allora la query
	%non puo' essere vuota, idem per @ in user ecc...)
	%Ci occupiamo dei problemi mediante la definizione di 
	%predicati specifici

	determine_fragment(Fragment, BooleanFrag),
	determine_query(Query, BooleanQuery),
	determine_authority(NewAuthHost, AuthorityPresence),

	generate_scheme(Scheme, SScheme),
	generate_userinfo(Userinfo, SUfo, BooleanU),
	generate_host(NewAuthHost, SHost, AuthorityPresence),
	generate_port(Port, SPort, BooleanPort),	
	generate_path(Path, SPath, BoolPAA),
	generate_query(Query, SQuery, BooleanQuery),
	generate_fragment(Fragment, SFrag, BooleanFrag),


	%siamo quindi pronti a restituire il risultato
	URI = uri(SScheme, SUfo, SHost, SPort, SPath, SQuery, SFrag).

%questo predicato e' veramente deprecabile, ma ho messo le cose cosi'
%perche' si realizzasse:
%"Notate che nel corso dellÕelaborazione potrebbe essere necessario 
%gestire le stringhe in 
%termini di liste di caratteri, utilizzando i predicati di 
%conversione %string_to_list e 
%string_to_atom1.  Tali liste non vengono per˜ visualizzate in modo 
%leggibile da 
%parte di utenti umani, e.g., ÓhttpÓ potrebbe essere visualizzata com%[104, 116, 116, 112]. 
%Nella costruzione del termine composto uri  richiesta lÕeventuale 
%conversione da liste di questo genere a stringhe leggibili. 
%La costruzione di un predicato invertibile in grado di risolvere 
%questo problema non  
%immediata, per˜, il vostro programma dovrebbe essere in grado di %
%rispondere 
%correttamente a query nelle quali i termini siano parzialmente 
%istanziati, come ad esempio: 
%?- parsed_uri(Óhttp://disco.unimib.itÓ, 
%               uri('https', _, _, _, _, _, _)). 
%No 
%?- parsed_uri(Óhttp://disco.unimib.itÓ, 
%               uri(_ ,_ , Host, _, _, _, _)). 
%Host = Õdisco.unimib.itÕ "
%Non mi sarebbe stato certo difficile costruire un uri/7 diverso, ma
%per come ho scritto il programma e per cosa e' richiesto questa e'
%la mia soluzione

uri(_, _, _, _, _, _, _).


%Predicati per verificare l' esistenza delle componenti dell' uri ed
%agire di conseguenza. Poiche' non accettiamo uri in cui, ad esempio,
%rintracciamo la presenza di delimitatori senza i rispettivi campi
%delimitati (ad. es. appare il # di fragment ma il frammento vuoto),
%teniamo traccia man mano della genuinita' di risultati non nulli e
%nulli mediante una variabile booleana.
%L' idea e', per ogni componente, verificarne l' esistenza e tenerne
%a mente subito il contenuto, che sara' poi esaminato in seguito.

%L' authority e' leggermente piu' complessa da identificare rispetto
%alle altre parti, poiche' oltre alla sua esistenza dobbiamo anche
%decidere dove andare in seguito
verify_authority(Sstring, AuthorityPresence) :-
	nth1(1, Sstring, ':'),
	nth1(2, Sstring, '/'),
	nth1(3, Sstring, '/'),
	AuthorityPresence = 1,
	!.
verify_authority(_, AuthorityPresence) :-
	AuthorityPresence = 0.
	
decide_authority(Rest1, AuthorityPresence, Next) :-
	AuthorityPresence == 1,
	crack_string(Rest1, Rest1, :, _, Rest2),
	crack_string(Rest2, Rest2, /, _, Rest3),
	crack_string(Rest3, Rest3, /, _, Next),
	!.
decide_authority(Rest1, AuthorityPresence, Next) :-
	AuthorityPresence == 0,
	cutFirst(Rest1, Next).



verify_fragment(Sstring, Etc, Fragment, BooleanFragment) :-
	member('#', Sstring),
	%no backtrack, ci basta la prima occorrenza, che e' quella
	%del separatore
	!,	
	crack_string(Sstring, Sstring, '#', Etc, Fragment),
	BooleanFragment = 1.
verify_fragment(Sstring, Etc, Fragment, BooleanFragment) :-
	notMember('#', Sstring),
	Fragment = [],
	Etc = Sstring,
	BooleanFragment = 0.

verify_query(Sstring, Etc, Query, BooleanQuery) :-
	member('?', Sstring),
	!,
	crack_string(Sstring, Sstring, '?', Etc, Query),
	BooleanQuery = 1.
verify_query(Sstring, Etc, Query, BooleanQuery) :-
	notMember('?', Sstring),
	Query = [],
	Etc = Sstring,
	BooleanQuery = 0.

define_path(Sstring, Etc, Path, AuthorityPresence, PAfterAuth) :-
	AuthorityPresence == 1,
	verify_path0(Sstring, Etc, Path, PAfterAuth),
	!.
define_path(Sstring, Etc, Path, AuthorityPresence, PAfterAuth) :-
	AuthorityPresence == 0,
	Etc = [],
	Path = Sstring,
	PAfterAuth = 0.
verify_path0(Sstring, Etc, Path, PAfterAuth) :-
	member('/', Sstring),
	!,
	crack_string(Sstring, Sstring, '/', Etc, Path),
	PAfterAuth = 1.
verify_path0(Sstring, Etc, Path, PAfterAuth) :-
	notMember('/', Sstring),
	Path = [],
	Etc = Sstring,
	PAfterAuth = 0.

	

verify_port(Sstring, Etc, Port, AuthorityPresence, BooleanPort) :-
	AuthorityPresence == 1,
	member(':', Sstring),
	!,
	crack_string(Sstring, Sstring, ':', Etc, Port),
	BooleanPort = 1.
verify_port(Sstring, Etc, Port, _, BooleanPort) :-
	notMember(':', Sstring),
	Port = [],
	Etc = Sstring,
	BooleanPort = 0.

verify_userinfo(Sstring, Etc, Userinfo, BooleanA, BooleanUserinfo) :-
	BooleanA == 1,
	member('@', Sstring),
	!,
	crack_string(Sstring, Sstring, '@', Userinfo, Etc),
	BooleanUserinfo = 1.
verify_userinfo(Sstring, Etc, Userinfo, _, BooleanUserinfo) :-
	notMember('@', Sstring),
	Userinfo = [],
	Etc = Sstring,
	BooleanUserinfo = 0.



%predicati per determinare la consistenza dell' uri
%Nel caso della path, se si e' in presenza di una path-after-auth,
%e' validata la simple path e poi attaccata '/'
determine_fragment(Fragment, BooleanFrag) :-
	BooleanFrag == 1,
	Fragment \= [],
	!.
determine_fragment(Fragment, BooleanFrag) :-
	BooleanFrag == 0,
	Fragment == [].

determine_query(Query, BooleanQuery) :-
	BooleanQuery == 1,
	Query \= [],
	!.
determine_query(Query, BooleanQuery) :-
	BooleanQuery == 0,
	Query == [].

determine_authority(Authority, AuthorityPresence) :-
	AuthorityPresence == 0,
	Authority == [],
	!.
determine_authority(Authority, AuthorityPresence) :-
	AuthorityPresence == 1,
	Authority \= [].

%user e porta hanno senso solo se authority e' ben definito, ovvero
%se host e' definito (non e' nullo)...
%Se l' host e' presente determiniamo anche la consistenza degli 
%eventuali userinfo & port


determine_userinfo(Userinfo, BooleanUserinfo) :-
	BooleanUserinfo == 1,
	Userinfo \= [],
	!.
determine_userinfo(Userinfo, BooleanUserinfo) :-
	BooleanUserinfo == 0,
	Userinfo == [].

determine_port(Port, BooleanPort) :-
	BooleanPort == 1,
	Port \= [],
	!.
determine_port(Port, BooleanPort) :-
	BooleanPort == 0,
	Port == [].


		
%predicati per chiamare i predicati di correttezza e convertire ad
%atomo normale; mandiamo anche la variabile booleana affinche'
%possiamo subito convertire in lista vuota una parte non presente,
%senza verificarla (la lista vuota non dev' essere controllata).
%lo scheme ci deve essere, validiamolo direttamente.
%Nel caso di presenza di path-after-authority considero parte 
%integrante del path anche il primo '/' caratteristico, vista la 
%grammatica
generate_scheme(Scheme, SScheme) :-
	validate_scheme(Scheme),
	string_to_atom(Scheme, SScheme).

generate_userinfo(Userinfo, SUfo, BooleanUserinfo) :-
	BooleanUserinfo == 1,
	validate_userinfo(Userinfo),
	string_to_atom(Userinfo, SUfo),
	!.
generate_userinfo(Userinfo, SUfo, BooleanUserinfo) :-
	BooleanUserinfo == 0,
	string_to_atom(Userinfo, SUfo).

generate_host(Host, SHost, BooleanHost) :-
	BooleanHost == 1,
	validate_host(Host),
	string_to_atom(Host, SHost),
	!.
generate_host(Host, SHost, BooleanHost) :-
	BooleanHost == 0,
	string_to_atom(Host, SHost).

generate_port(Port, SPort, BooleanPort) :-
	BooleanPort == 1,
	validate_port(Port),
	string_to_atom(Port, SPort),
	!.
generate_port(Port, SPort, BooleanPort) :-
	BooleanPort == 0,
	string_to_atom(Port, SPort).

generate_path(Path0, SPath, BoolPAA) :-
	refine_path(Path0, BoolPAA, Path, Bool),
	Bool = 1,
	cutFirst(Path, Path1),
	validate_path0(Path1),
	string_to_atom(Path, SPath),
	!.
generate_path(Path0, SPath, BoolPAA) :-
	refine_path(Path0, BoolPAA, Path, Bool),
	Bool = 0,
	validate_path0(Path),
	string_to_atom(Path, SPath).
refine_path(Path, BoolPAA, NewPath, Bool) :-
	BoolPAA = 1,
	append(['/'], Path, NewPath),
	Bool = 1,
	!.
refine_path(Path, _, NewPath, Bool) :-
	NewPath = Path,
	Bool = 0.

generate_query(Query, SQuery, BooleanQuery) :-
	BooleanQuery == 1,
	validate_query(Query),
	string_to_atom(Query, SQuery),
	!.
generate_query(Query, SQuery, BooleanQuery) :-
	BooleanQuery == 0,
	string_to_atom(Query, SQuery).

generate_fragment(Fragment, SFragment, BooleanFragment) :-
	BooleanFragment == 1,
	validate_fragment(Fragment),
	string_to_atom(Fragment, SFragment),
	!.
generate_fragment(Fragment, SFragment, BooleanFragment) :-
	BooleanFragment == 0,
	string_to_atom(Fragment, SFragment).



%predicati per la correttezza carattere per carattere delle parti
digit('0').
digit('1').
digit('2').
digit('3').
digit('4').
digit('5').
digit('6').
digit('7').
digit('8').
digit('9').
%dividiamo l' ip in quattro parti delimitate dai tre '.'; ogni parte
%puo' essere del tipo N, NN, NNN e deve essere un 'ottetto' (in
%realta' verifichiamo quel ch'e' chiesto nelle specifiche, ovvero che
%vi siano solo numeri).
validate_host(Ip) :-
	crack_string(Ip, Ip, '.', FirstOctet, Octets1),
	crack_string(Octets1, Octets1, '.', SecondOctet, Octets2),
	crack_string(Octets2, Octets2, '.', ThirdOctet, FourthOctet),
	length(FirstOctet, A),
	length(SecondOctet, B),
	length(ThirdOctet, C),
	length(FourthOctet, D),
	A > 0, A < 4,
 	B > 0, B < 4,
	C > 0, C < 4,
	D > 0, D < 4,
	octet(FirstOctet),
	octet(SecondOctet),
	octet(ThirdOctet),
	octet(FourthOctet).
%verifichiamo sia la presenza di soli caratteri leciti 
validate_host(Name) :- host(Name).
host(N) :- 
	length(N, 1),
	!, 
	N \= '/', 
	N \= '?', 
	N \= '#', 
	N \= '@', 
	N \= ':'.
host([N | Ns]) :-
	N \= '/', 
	N \= '?', 
	N \= '#', 
	N \= '@', 
	N \= ':',
	host(Ns).

octet(O) :- length(O, 1), nth0(0, O, E), digit(E), !.
octet([O | Os]) :- digit(O), octet(Os).

%-Giuseppe Vizzari - mercoled“, 25 febbraio 2009, 19:08
%Allora diciamo che la definizione di simple path viene emendata nel %seguente modo:
%simple-path ::= [Ô/Õ]<identificatore>[Ô/Õ simple-path]* | <vuoto>
%Il primo caso di validate_path0 copre i path minimi, piu' facili.
%L' obiettivo e', prima di verificare carattere per carattere, 
%controllare che il carattere lecito '/' non origini parti illecite:
%infatti secondo la grammatica data, vi possono essere sottoliste del
%tipo '//' ma non come prefisso o suffisso, e non '///' o oltre
validate_path0(Path) :-
	length(Path, X),
	X < 2,
	Path \= ['/'],
	validate_path1(Path),
	!.
validate_path0(Path) :- 
	not(sublist(['/', '/', '/'], Path)),
	Path \= ['/'],
	nth1(1, Path, A),
	nth1(2, Path, B),
	append([A], [B], P),
	P \= ['/', '/'],
	length(Path, L),
	nth1(L, Path, C),
	M is L-1,
	nth1(M, Path, D),
	append([C], [D], Q),
	Q \= ['/', '/'],
	validate_path1(Path),
	!.
validate_path1([]) :- !.
validate_path1([P | Pp]) :- 
	P \= '?', 
	P \= '#', 
	P \= '@', 
	P \= ':',
	validate_path1(Pp).


validate_scheme(S) :- 
	length(S, 1), 
	nth0(0, S, E),
	E \= '/', 
	E \= '?', 
	E \= '#', 
	E \= '@', 
	E \= ':',
	!.
validate_scheme([S | Ss]) :-
	S \= '/', 
	S \= '?', 
	S \= '#', 
	S \= '@', 
	S \= ':',
	validate_scheme(Ss).

validate_query(Q) :-
	length(Q, 1), 
	nth0(0, Q, E), 
	E \= '#'.
validate_query([Q | Qq]) :-
	Q \= '#',
	validate_query(Qq).

%un fragment puo' avere qualsiasi carattere...
validate_fragment(_).

%l' insieme di caratteri su cui insistono e' il medesimo
validate_userinfo(U) :- validate_scheme(U).

%nonostante il nome octet/1 verifica semplicemente che una lista sia
%di soli 0-9, e prevede come caso base una lista ad un solo numero
validate_port(P) :- octet(P).



%predicati di fix (vedi sopra)
set_proper(Scheme, Authority, NewAuth) :-
	Scheme = Authority,
	NewAuth = [],
	!.
set_proper(_, Authority, NewAuth) :-
	NewAuth = Authority.



%Il predicato crack_string/4, come "suggerisce" il nome, non fa altro
%che rompere in due parti una stringa, sottoforma di lista, in due 
%parti, e spartiacque e' un carattere fornito. Cosa importante e' che
%la stringa e' spezzata solo in base alla *prima* occorrenza del char
%e questo e' particolarmente utile ai nostri scopi, oltre che piu' 
%facile da implementare
%-Caso base: stringa vuota, non possiamo dividere un bel niente
%-Caso generico di successo: siamo nel caso in cui il carattere 
% corrente della stringa che esaminiamo e' lo spartiacque cercato:
% allora vediamo la sua posizione nella stringa originale (infatti 
% e' ovvio che non necessariamente lo spartiacque sia lo starting 
% char) cosa che abbiamo poiche' questa e' parametro, e creiamo la 
% prima sottostringa, quella prima dello spartiacque.
% La seconda e' creata con lo stesso predicato! Infatti basta:
% -invertire la stringa originale
% -calcolare la posizione opportuna, ovvero che fine faccia il char
%  dopo avere invertito l' ordine degli elementi in lista
% -re-invertire quello che otteniamo, dato che cerchiamo il "before"
%-Caso generico d' insuccesso: siamo nel caso in cui il carattere
% corrente non e' quello cercato e quindi continuiamo fiduciosi 
% ricorrendo
%-Caso generico d' impossibilita': se non e' possibile spaccare per
% un carattere una stringa poiche' questo non e' nella stringa, 
% restituiamo la stringa stessa sia come prefisso che suffisso, il 
% che e' ambiguo perche' sarebbe possibile solo per un carattere 
% vuoto
%
%From: Marco Antoniotti <marcoxa_at_cs.nyu.edu> 
%Date: Thu, 1 Mar 2007 20:58:26 +0100
%Think of a prodicate 
%        split_string(String, Separator, Before, After). 
%It will help. Predicates prefix/2 and suffix/2 will also help. 
%Cheers 

crack_string([], _, [], []) :- !.
crack_string(Original, [X | _], Char, Before, After) :-
	X = Char,
	nth1(N, Original, Char),
	create_crack(Original, N, Before),
	length(Original, L),
	M is L - N + 1,
	reverse(Original, OriginalReversed),
	create_crack(OriginalReversed, M, AfterReversed),
	reverse(AfterReversed, After),
	!. 
crack_string(Original, [X | Xs], Char, Before, After) :-
	!,
	X \= Char,
	crack_string(Original, Xs, Char, Before, After).
crack_string(Original, _, Char, Before, After) :-
	notMember(Char, Original),
	!,
	Before = Original,
	After = Original.	

create_crack([], _, []) :- !.
create_crack(_, 1, []) :- !.
create_crack([X | Xs], N, [Y | Ys]) :-
	Y = X,
	M is N-1,
	create_crack(Xs, M, Ys). 



codeListToCharList([], []) :- !.	
codeListToCharList([X | Xs], [Y | Ys]) :- 
	char_code(Y, X), 
	codeListToCharList(Xs, Ys).	
%predicato per "leggibilizzare" la lista: semplicemente facciamo 
%corrispondere ad ogni i-esimo elemento della lista output il 
%carattere rappresentato dall' i-esimo codice di quella in input.



notMember(_, _) :- !.
notMember(Elem, List):- member(Elem, List), !, fail. 

sublist(Ls, Ms) :- append(_, LL, Ms), append(Ls, _, LL), !.

cutFirst([_ | Xs], Xs).

%URI completo, con host obbligatorio per via di ftp:
%?- parsed_uri("ftp://reim@riqui.it:999//path/to/lol?asd#fef", L).
%L = uri(ftp, reim, 'riqui.it', '999', '/path/to/lol', asd, fef).
%-
%URI completo, con host obbligatoriamente mancante per via di fp:
%?- parsed_uri("fp://reim@riqui.it:999//path/to/lol?asd#fef", L).
%false.
%-
%Test fallito per via della presenza di '?' ma di una query vuota
%?- parsed_uri("ftp://reim@riqui.it:999//path/to/lol?#fef", L).
%false.
%-
%Test riuscito: la path e' correttamente letta, l' auth non ci deve
%proprio essere per via dello scheme
%?- parsed_uri("ft:/riqui.it/path/to/lol#fef", L).
%L = uri(ft, [], [], [], '/riqui.it/path/to/lol', [], fef).
%-
%Il test fallisce poiche' non vi puo' essere una path che abbia tre
%'/' di fila senza nessuna stringa identificatore tra essi
%?- parsed_uri("ft:/riqui.it///path/to/lol", L).
%false.
%-
%Invertibilita':
%?- parsed_uri("ftp://unimib.it/", uri('ftp', _, L, _, _, _, _)).
%L = 'disco.unimib.it'.
%-
%Bastardine:
%?- parsed_uri("d?:/", L).
%false.
%?- parsed_uri("d#:/", L).
%false.

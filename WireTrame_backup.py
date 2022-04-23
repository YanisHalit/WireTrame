#!/usr/bin/env python3
import string
import sys

### Variable globale ###
ip_source = ""
ip_destination = ""
mac_source = ""
mac_destination = ""
taille_ethernet = 14
taille_ip = 0
taille_udp = 0
taille_dhcp = 0
taille_dns = 0
taille_tot = 14

L_TAILLE = list(dict()) # liste de dictionnaires ou chaque L_TAILLE[i] représente les tailles des differentes couches sous forme d'un dictionnaire
TREE_FATHER = list() # Premier niveau de notre tree de forme (f'{ip_source}', f'{ip_destination}', f'{P_ACTU}', f'{L_TAILLE[T_ACTU].get("tot")}')
TREE_CHILDREN = list() # Deuxieme niveau de notre tree ({"ETHERNET":"","IP":"","UDP":"","DHCP":"", "DNS":""})
RES = list() # liste de dict ou chaque RES[i] on a {ETHERNET,IP,UDP,DHCP,UDP} en clés avec pour valeur le message receuilli dans le champ
T_ACTU = 0 # n° de trame actuelle (la première étant à 0)

P_ACTU = "" # nom du protocole de la trame n° T_ACTU
BOOL = False

def lecture_fichier(file=''):
	if file != '' :
		file = open(file, "r")
		r = file.readlines()
		if len(r) == 0:  # Cas si le fichier est vide
			print("Fichier inaccessible ou inexistant ou vide")
			return
		else :
			return r


	fichier = input("Quel fichier voulez-vous lire ? ")
	try:
		file = open(fichier, "r")
	except:
		print("Le fichier", fichier, "est introuvable, veuillez réessayer.")
		return lecture_fichier()


	r = file.readlines() #retourne toute la lignes sous forme d'une liste ou chaque élement représente une ligne
	return r

def lecture_octet(lignes, i, col, nboct_lu, nboct_alire, nblu_oblig):
	"""lit (nboct_alire-nblu_oblig) octets situés en ligne i à partir de la position col sur la ligne.
	Et retourne les caractères lus si se sont des octets ou des offsets."""

	offset = ""
	Source = ""

	if nboct_lu < nblu_oblig:
		print("Problème d'octets lus.")
		sys.exit("Problème d'octets.")

	col2 = col

	while i < len(lignes) and nboct_lu < nboct_alire:
		booli = True
		ligne = lignes[i]
		if col2 == 0:
			offset = det_offset(lignes,i,col2)
			while col2 < len(ligne) and offset == "":
				booli = False
				col2 += 1
				offset = det_offset(lignes,i,col2)

			if offset == '0000 ' and nboct_lu != 0:
				booli = False
				col2 = 0

			elif offset == "":
				booli = False
				col2 = 0

			elif offset != "":
				booli = True
				a = int(offset,16)
				col2 = 5
				if a != nboct_lu:
					if a == 0 :
						return [i-1,col2,nboct_lu,Source]
					else:
						print("Il y a une erreur avec la valeur de l'offset en ligne: ", i+1)
						sys.exit("Erreur offset.")
						booli=False
						col2=0

		if booli :
			while col2 < len(ligne) and nboct_lu < nboct_alire:
				if ligne[col2]==' ':
					col2 += 1

				elif ligne[col2] == '\n':
					col2 = 0
					break

				elif is_octet(lignes,i,col2):
					if col2+1 < len(ligne) and ligne[col2+1] in string.hexdigits:
						nboct_lu += 1
						Source += ligne[col2]+ligne[col2+1]

						if nboct_lu < nboct_alire:
							Source += ':'
						col2 += 2

					else:
						print("Erreur, ligne ", i+1, "incomplète ou fausse")
						sys.exit("Erreur, ligne incomplète ou fausse")
				else:
					col2 += 1

		i += 1
	return [i-1, col2, nboct_lu, Source]

def lecture_octet2(lignes, i, col, nboct_lu, nboct_alire, nblu_oblig):
	""" Même fonction que la précedente si ce n'est que la séparation se fait avec des espaces """
	offset=""
	Source=""

	if nboct_lu < nblu_oblig:
		print("Nous n'avons pas lu assez d'octet !")
		sys.exit("Problème d'octets.")

	col2=col
	while i<len(lignes) and nboct_lu < nboct_alire:

		booli=True
		ligne=lignes[i]
		if col2 == 0:
			offset = det_offset(lignes,i,col2)
			while col2 < len(ligne) and offset=="":
				booli = False
				col2 += 1
				offset = det_offset(lignes,i,col2)

			if offset=='0000 ' and nboct_lu != 0:
				booli = False
				col2 = 0

			if offset == "":
				booli = False
				col2 = 0

			elif offset != "":
				booli = True
				a = int(offset,16)
				col2 = 5
				if a != nboct_lu:
					if a==0:
						return [i-1,col2,nboct_lu,Source]
					else:
						print("Il y a une erreur avec la valeur de l'offset en ligne: ",i+1,". Offsset Lu:", a,", Offset Attendu", nboct_lu)
						sys.exit("Erreur offset.")
						booli=False
						col2=0

		if booli:
		#on cherche à trouver la source
			while col2<len(ligne) and nboct_lu < nboct_alire:
				if ligne[col2] == ' ':
					col2+=1

				elif ligne[col2] == '\n':
					col2=0
					break

				elif is_octet(lignes,i,col2):
					if col2+1<len(ligne) and ligne[col2+1] in string.hexdigits:
						nboct_lu +=1
						Source += ligne[col2]+ligne[col2+1]
						col2+=2

					else:
						print("Attention en ligne ",i+1, " incomplète ou fausse")
						sys.exit("Erreur, ligne incomplète ou fausse")
				else:
					col2+=1

		i+=1

	return [i-1, col2, nboct_lu, Source]

def is_offset(lignes,i,col2):
	""" Retourne True ou False selon si les caractères sont des offsets """
	ligne = lignes[i]
	if col2 == 0 and len(lignes[i]) < 4:
		if lignes[i][0]!= '\n':
			print("La Ligne ",i+1," doit commencer par un offset !")
			sys.exit()

	if col2 < len(ligne) and ligne[col2] not in string.hexdigits:
		return False

	if col2 > 0 :
		if ligne[col2-1] != ' ':
			return False

	suiv = col2+1

	if suiv >= len(ligne):
		print("Problème en ligne: ",i+1,", un caractère est isolé.")
		sys.exit("Erreur Ligne incomplète !")

	if ligne[suiv] not in string.hexdigits:
		if ligne[suiv]==' ' or ligne[suiv]=='\n':
			print("Problème en ligne: ",i+1,", caractère non hexadécimal.")
			sys.exit("Erreur Ligne incomplète !")
		return False

	plus = col2+4
	if plus < len(ligne):
		if ligne[plus] != ' ' and ligne[plus] != '\n':
			return False

	return True

def is_octet(lignes,i,col2):
	"""retourne si True ou False selon si le string actuelle (en ligne i, position col2) est un octet"""
	ligne = lignes[i]

	if ligne[col2] not in string.hexdigits:
		return False

	if col2 > 0 :
		if ligne[col2-1] != ' ':
			return False

	suiv = col2+1

	if suiv >= len(ligne):
		print("Problème en ligne: ",i+1, ", un caractère est peut etre mal placé ou ne devrait pas être placé !")
		sys.exit("Erreur Ligne incomplète !")

	if ligne[suiv] not in string.hexdigits:
		if ligne[suiv] == ' ' or ligne[suiv] == '\n':
			print("Problème en ligne: ",i+1," CARACTERE ",col2)
			sys.exit("Erreur Ligne incomplète !")
		return False

	plus=col2 + 2
	if plus < len(ligne):
		if ligne[plus] != ' ' and ligne[plus] != '\n':
			return False

	return True

def det_offset(lignes,i,col2):
	""" determine l'offset de la ligne i à partir du caractère col2 """
	offset = ""
	ligne = lignes[i]
	if is_offset(lignes,i,col2):
		if col2+4 < len(ligne):
			for x in range(col2, col2+5):
				if x < len(ligne):
					offset += ligne[x]
		else:
			for x in range(col2,col2+4):
				if x < len(ligne):
					offset+=ligne[x]

	return offset

def reset():
	""" Réinitialise certaines variable globale nécessaire pour gestion interface graphique """
	global taille_ip, taille_udp, taille_dhcp, taille_dns, taille_tot, ip_source, ip_destination, mac_source, mac_destination, P_ACTU
	ip_source = ""
	ip_destination = ""
	mac_source = ""
	mac_destination = ""
	taille_ip = 0
	taille_udp = 0
	taille_dhcp = 0
	taille_dns = 0
	taille_tot = 14
	P_ACTU = ""

def reset_list():
	""" réinitialiser certaines variable globales nécessaire pour l'interface graphique lors du passage d'une trame à une autre """
	global T_ACTU, RES, L_TAILLE, TREE_FATHER, TREE_CHILDREND, BOOL
	del RES[:]
	del TREE_FATHER[:]
	del TREE_CHILDREN[:]
	del L_TAILLE[:]
	B = True
	T_ACTU = 0

def execution(fichier):
	""" Analyse d'une trace """

	global taille_ethernet, taille_ip, taille_udp, taille_dhcp, taille_dns, taille_tot
	global ip_source, ip_destination, mac_source, mac_destination, P_ACTU
	global T_ACTU, RES, L_TAILLE, TREE_FATHER, TREE_CHILDREND

	f = open("Résultats.txt","w")

	if fichier == "":
		lignes = lecture_fichier()
	else :
		lignes = lecture_fichier(fichier)

	i = 0
	res = ""
	while i < len(lignes):
		offset = ""
		offset = det_offset(lignes,i,0)
		if offset == "0000 ":
			reset()
			RES.append({"ETHERNET":"","IP":"","UDP":"","DHCP":"", "DNS":""})
			TREE_CHILDREN.append({"ETHERNET":"","IP":"","UDP":"","DHCP":"", "DNS":""})
			analyse = lecture_Ethernet(lignes,i,0)
			L_TAILLE.append({"tot":taille_tot, "ethernet":14, "ip":taille_ip, "udp":taille_udp, "dhcp":taille_dhcp, "dns": taille_dns})
			TREE_FATHER.append((f'{ip_source}', f'{ip_destination}', f'{P_ACTU}', f'{L_TAILLE[T_ACTU].get("tot")}'))
			res = "Trame n°"+ str((T_ACTU+1)) +": " + str(analyse[1]) + " bytes on wire (" + str( analyse[1]*8 )+' bits)\n' + analyse[0] + "\n\n"
			f.write(res)
			f.write('==========================================================================================================================================================================================================\n')
			T_ACTU += 1
			i += 1
		else :
			i += 1

	if res == "":
		print("Pas de trame à analyser ? Verifiez bien votre lignes, il n'y a peut être pas d'offset")
		sys.exit()

	f.close()

def lecture_Ethernet(lignes, li, nboct_lu):
	""" Renvoie l'analyse de toute la trame en appelant lecture_IP, la taille totale de la trame
		ainsi que le nombre d'octets lu au total """
	i = li
	MSG_DEBUT = "Ethernet II, "
	Message = ""
	c = ""
	L = []
	nbcol2 = 0
	nboct_lu = nboct_lu
	TOT_LEN = 14

	L = lecture_octet(lignes, i, nbcol2, nboct_lu, 6, 0)
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	Message += '\t'+"Destination: "+L[3]+'\n'
	global mac_destination
	mac_destination = L[3]
	MSG_TMP = "Dst: (" + mac_destination + ")\n"

	L = lecture_octet(lignes, i, nbcol2, nboct_lu, 12, 6)
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	global mac_source, T_ACTU, RES,	TREE_CHILDREN
	mac_source = L[3]
	MSG_DEBUT += "Src: (" + mac_source + "), " + MSG_TMP
	Message += '\t'+"Source: "+L[3]+'\n'
	L = lecture_octet2(lignes, i, nbcol2, nboct_lu, 14, 12)
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	s= '??'
	if L[3] == '0800':
		s = ' IPV4 '
	if L[3] == '0806':
		s = ' ARP '
	Message += '\t'+"Type: "+ s +'(0x' + L[3] + ')\n'

	TREE_CHILDREN[T_ACTU].update(ETHERNET = MSG_DEBUT.replace("\n",""))

	MSG_DEBUT += Message
	Message = MSG_DEBUT

	RES[T_ACTU].update(ETHERNET = Message+"\n")

	if L[3] == '0800':
		X = lecture_IP(lignes, i, nbcol2, nboct_lu)
		TOT_LEN += X[2]
		Message += X[1]
		nboct_lu = X[0]

	elif L[3] != '0800':
		print("\nAttention! a valeur type d'ETHERNET ne correspond pas à celle d'IPv4, je ne peux pas analyser la suite de la trame, ligne: ", i+1)


	return [Message,TOT_LEN, i]

# return [nboct_lu,Message,TOT_LEN]
def lecture_IP(lignes, li, nbcol, nboct_l):
	""" Analyse la séquence IP ainsi que ses options si elles sont présentes """
	opt = True
	s = ""
	i = li
	MSG_DEBUT = "\nInternet Protocol Version "
	Message = ""
	L = []
	nbcol2 = nbcol
	nboct_lu = nboct_l
	L = lecture_octet(lignes, i, nbcol2, nboct_lu, 15, 14)
	IHL = int(L[3][1],16) * 4
	global taille_ip
	taille_ip = IHL
	if IHL < 20:
		print("Erreur en ligne ",i+1,", taille de l'en-tête ip trop petite.")
		return
	if IHL == 20:
		opt = False
	if IHL > 60:
		print("Erreur en ligne ",i+1,", taille de l'en-tête trop grande.")
		return
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]

	if L[3]:
		Message += '\tVersion: ' + str(int(L[3][0],16)) +'\n'
		MSG_DEBUT += str(int(L[3][0],16)) + ", "
		Message +='\tHeader Length: ' + str(int(L[3][1],16)*4) + " bytes (" + str(int(L[3][1],16)) + ')\n'

	L = lecture_octet(lignes, i, nbcol2, nboct_lu, 16, 15)
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]

	if L[3]:
		c = "\tDifferentiated Services Field: 0x"+ L[3]+"\n"
		c2 = bin(int(L[3],16))[2:].zfill(8)
		c += '\t  '+ c2[:4] +' '+ c2[4:6] + '.. = Differentiated Services Codepoint: Default (0)\n'
		Message += c
		c = '\t  .... ..' + c2[6:]+ ' = Explicit Congestion Notification\n'
		Message += c

	L = lecture_octet2(lignes, i, nbcol2, nboct_lu, 18, 16)
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	TOT_LEN = 0
	if L[3]:
		TOT_LEN = int(L[3],16)
		global taille_tot
		taille_tot += TOT_LEN
		Message += '\tTotal length ' + str(TOT_LEN) +' bytes (0x' + L[3] + ')\n'
	L=lecture_octet2(lignes, i, nbcol2, nboct_lu, 20, 18)
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	if L[3]:
		Message += '\tIdentification: 0x' + L[3] + ' (' + str(int(L[3],16)) + ')\n'
	L = lecture_octet2(lignes, i, nbcol2, nboct_lu, 22, 20)
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]

	if L[3]:
		c = '\tFlags: 0x' + L[3] + ',\n'
		flag = bin(int(L[3],16))[2:].zfill(16)
		s1 = 'Not Set'
		s2 = 'Not Set'
		s3 = 'Not Set'
		if int(flag[0]) == 1:
			s1 = 'Set'
		if int(flag[1]) ==1 :
			s2 = 'Set'
		if int(flag[2]) == 1:
			s3 = 'Set'

		if s2 != s3 and s2 == "Set":
			c = '\tFlags: 0x' + L[3] + ", Don't Fragment\n"
			c += "\t\t" + flag[0] + "... .... .... .... = Reserved bit: " + s1 + '\n'
			c += "\t\t."+ flag[1] + ".. .... .... .... = Don't Fragment: " + s2 + '\n'
			c += "\t\t.."+ flag[2] + ". .... .... .... = More Fragments: " + s3 + '\n'

		if s2 != s3 and s3 == "Set":
			c = '\tFlags: 0x' + L[3] + ", More Fragment\n"
			c += "\t\t" + flag[0] + "... .... .... .... = Reserved bit: " + s1 + '\n'
			c += "\t\t." + flag[1] + ".. .... .... .... = Don't Fragment: " + s2 + '\n'
			c += "\t\t.." + flag[2] + ". .... .... .... = More Fragments: " + s3 + '\n'

		if s2 == s3 and s3 == "Set":
			c = '\tFlags: 0x' + L[3] + ", More fragment, Don't Fragment\n"
			c += "\t\t" + flag[0] + "... .... .... .... = Reserved bit: " + s1 + '\n'
			c += "\t\t." + flag[1] + ".. .... .... .... = Don't Fragment: " + s2 + '\n'
			c += "\t\t.." + flag[2] + ". .... .... .... = More Fragments: " + s3 + '\n'

		if s2 == s1 and s1 == 'Not Set' :
			c='\tFlags: 0x' + L[3] +'\n'
			c+="\t\t" + flag[0] + "... .... .... .... = Reserved bit: " + s1 + '\n'
			c+="\t\t."+ flag[1] + ".. .... .... .... = Don't Fragment: " + s2 + '\n'
			c+="\t\t.."+ flag[2] + ". .... .... .... = More Fragments: " + s3 + '\n'
		fragg = flag[3:]
		c += "\t\t..." + flag[3] + ' ' + flag[4:8] + ' ' + flag[8:12] + ' ' + flag[12:16] + ' = Fragment Offset: ' + str(int(fragg,16)) + '\n'
		Message += c

	L = lecture_octet2(lignes, i, nbcol2, nboct_lu, 23, 22)
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	if L[3]:
		a = str(int(L[3],16))
		Message += '\tTime To Live: '+ a + ' (' + L[3] + ')\n'

	L = lecture_octet2(lignes, i, nbcol2, nboct_lu, 24, 23)
	i = L[0]
	actu_i = i
	nbcol2 = L[1]
	nboct_lu = L[2]

	if L[3]:
		proto = int(L[3],16)
		p = '??'

	if proto == 17:
		p = 'UDP'

	if proto != 17:
		print("\nAttention! cet analyseur ne considére que le protocole UDP\n")
		return [nboct_lu,Message,TOT_LEN]

	Message += '\tProtocol: ' + p + ' (' + str(proto) + ')\n'

	L = lecture_octet2(lignes, i, nbcol2, nboct_lu, 26, 24)
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	Message += '\tHeader Checksum: 0x' + L[3] + '\n'
	Message += '\t[Header Checksum Status: unverified]' + '\n'
	L = lecture_octet(lignes, i, nbcol2, nboct_lu, 30, 26)
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]

	tmp = ''
	ip = ''

	for j in range (len(L[3])):
		if L[3][j] != ':':
			tmp += L[3][j]
		if L[3][j] == ':':
			actu = str(int(tmp, 16))
			ip += actu + '.'
			tmp = ''
		if j == len(L[3])-1:
			actu = str(int(tmp,16))
			ip += actu
			tmp = ''
	global ip_source
	ip_source = ip
	MSG_DEBUT += "Src: " + ip_source + ", "
	c = '\tSource:  '+ ip +'\n'
	Message += c

	L = lecture_octet(lignes, i, nbcol2, nboct_lu, 34, 30)
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	tmp = ''
	ip = ''

	for j in range (len(L[3])):
		if L[3][j] != ':':
			tmp += L[3][j]
		if L[3][j] == ':':
			actu = str(int(tmp,16))
			ip += actu + '.'
			tmp = ''
		if tmp and j == len(L[3])-1:
			actu = str(int(tmp,16))
			ip += actu
			tmp = ''

	global ip_destination, T_ACTU, RES, TREE_CHILDREN
	ip_destination = ip
	MSG_DEBUT += "Dst: " + ip_destination + "\n"
	c = '\tDestination:  ' + ip +'\n'
	Message += c
	TREE_CHILDREN[T_ACTU].update(IP = MSG_DEBUT.replace("\n",""))

	MSG_DEBUT += Message
	Message = MSG_DEBUT

	if opt:
		EO = etude_option_ip(lignes, i, nbcol2, nboct_lu, IHL)
		nboct_lu = EO[0]
		i = EO[1]
		nbcol2 = EO[2]
		Message += EO[3]

	RES[T_ACTU].update(IP = Message[1:]+"\n")

	# reste_alire = TOT_LEN - IHL
	if proto == 17:
		Message += "\nUser Datagram Protocol, "
		L = etude_UDP(lignes,i,nbcol2,nboct_lu)
		Message += L

	else :
		Message += "\nAttention! le trame présente une erreur sur la ligne: ", i+1, " UDP ne peut avoir que 67 OU 53 comme valeur pour le port destination\n"
		return [nboct_lu,Message,TOT_LEN]

	return [nboct_lu,Message,TOT_LEN]

# return [nboct_lu,i,nbcol2,Message]
def etude_option_ip(lignes, i, nbcol2, nboct_lu, IHL):
	""" Retourne l'analyse des options IP si elles existent """
	Message = ""
	type_opt = ""
	len_opt = ""
	point_opt = ""
	L = lecture_octet2(lignes, i, nbcol2, nboct_lu, 35, 34)
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]

	if L[3]:
		type_opt += L[3][0] + L[3][1]
	if type_opt:
		type_opt = int(type_opt, 16)
		Message += '\t\tType: ' + str(type_opt) + '\n'

	L = lecture_octet2(lignes, i,nbcol2, nboct_lu, 36, 35)
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	if L[3]:
		len_opt += L[3][0]+ L[3][1]
	if len_opt:
		len_opt = int(len_opt,16)
		Message += '\t\tLength: ' + str(len_opt) + '\n'

	L = lecture_octet2(lignes, i, nbcol2, nboct_lu, 37, 36)
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]

	if len(L[3]) >= 2:
		point_opt += L[3][0] + L[3][1]
		point_opt = int(point_opt, 16)
		Message += '\t\tPointer: '+ str(point_opt) + '\n'

	if len_opt and 20+len_opt > IHL:
		print("Mauvais IHL.")
		return [nboct_lu,i,nbcol2,Message]

	r = 35
	h = ""
	z = 41
	k = 37
	s = ""
	if type_opt == 0:
		s = "End of Options List"
	if type_opt == 1:
		s = "No Operation"
	if type_opt == 130:
		s = "Security"
	if type_opt == 131:
		s = "Loose Source Route"
	if type_opt == 68:
		s = "Time Stamp"
	if type_opt == 133:
		s = "Extended Security"
	if type_opt == 134:
		s = "Commercial Security"

	if type_opt == 7:
		s = "Record Route"
		while z < len_opt + r:
			L = lecture_octet2(lignes, i, nbcol2, nboct_lu, z, k)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			z += 4
			k += 4
			if L[3]:

				check = False
				for j in range(0, len(L[3])):
					if L[3][j] != "0" and L[3][j] != ':':
						check = True
						break

				tmp = ''
				ip = ''

				for j in range (len(L[3])):
					if L[3][j] != ':':
						tmp += L[3][j]
					if L[3][j] == ':':
						actu = str(int(tmp, 16))
						ip += actu + '.'
						tmp = ''
					if j == len(L[3])-1:
						actu = str(int(tmp,16))
						ip += actu
						tmp = ''
				if check == False and L[3]:
					h += "\t \tEmpty Route: "+ ip +'\n'


				if check == True and L[3]:
					h += "\t \tRecorded Route: "+ ip +'\n'

	if type_opt == 136:
		s="Stream ID"
	if type_opt == 137:
		s="Strcit Source route"
	if type_opt == 10:
		s="Experimental Measurement"
	if type_opt == 11:
		s="MTU Probe"
	if type_opt == 12:
		s="MTU Reply"
	if type_opt == 205:
		s="Experimental Flow Control"
	if type_opt == 142:
		s="Experimental Access Control"
	if type_opt == 144:
		s="IMI Traffic Descriptor"
	if type_opt == 145:
		s="Extended Internet Protocol"
	if type_opt == 82:
		s="Traceroute"
	if type_opt == 147:
		s="Adress Extension"
	if type_opt == 148:
		s="Router Alert"
	if type_opt == 149:
		s="Selective Directed Broadcast"
	if type_opt == 150:
		s="Unassigned"
	if type_opt == 151:
		s="Dynamic Packet State"
	if type_opt == 152:
		s="Upstream Multicast Pkt"
	if type_opt == 25:
		s="Quick Start"
	if type_opt == 30 or type_opt == 94 or type_opt == 158 or type_opt == 222:
		s="RFC3692-style Experiment"

	if nboct_lu and len_opt:
		z = nboct_lu + len_opt + 1
		nboct_lu += 1
		nbcol2 += 4

	Message = "\n\tIP Options - " + s + " (" + str(IHL-21) + " bytes)\n" + Message
	Message += h

	Mess = ""
	pad = 0
	IHL_bit = IHL * 8
	while (IHL_bit % 32) != 0 :
		L = lecture_octet2(lignes,i,nbcol2,nboct_lu,z,k)
		Mess += L[3]+' '
		i = L[0]
		nbcol2 = L[1]
		nboct_lu = L[2]
		z += 1
		k += 1
		IHL_bit += 8
		pad += 1

	if nboct_lu and len_opt:
		k = nboct_lu + len_opt + 1
	if Mess != "":
		Message += "\tPadding ("+ str(pad)+ " bytes" +"):" + Mess + '\n\n'
	else:
		Message += "\tIP Option - End Of Options List (EOL)\n\t\tType: 0\n"
		Message += "\t\t\t0... .... = Copy On fragmentation: No\n\t\t\t.00. .... = Class: Control (0)\n\t\t\t...0 0000 = Number: End of Option List (EOL) (0)\n"



	return [nboct_lu,i,nbcol2,Message]

# return Message + M_tmp
def etude_UDP(lignes,i,nbcol2,nboct_lu):
	""" Retourne l'analyse de UDP  """
	global T_ACTU, RES, P_ACTU, taille_dhcp, taille_dns, taille_udp
	octlu_udp = 0
	a_lire = nboct_lu + 2
	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	a_lire += 2
	octlu_udp += 2
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	port_src_int = int(L[3],16)
	port_src = str(port_src_int)

	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	a_lire += 2
	octlu_udp += 2
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	port_dst_int = int(L[3],16)
	port_dst = str(port_dst_int)

	Message = "Src Port:" + port_src + ", Dst Port: " + port_dst
	global TREE_CHILDREN
	TREE_CHILDREN[T_ACTU].update(UDP= ("User Datagram Protocol, "+Message).replace("\n",""))
	Message += "\n\tSource port: " + port_src + "\n\tDestination Port: " + port_dst

	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	a_lire += 2
	octlu_udp += 2
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	lenint_udp = int(L[3],16)
	len_udp = str(int(L[3],16))
	Message += "\n\tLength: " + len_udp
	taille_udp = 8

	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	a_lire += 2
	octlu_udp += 2
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	check_sum = L[3]
	Message += "\n\tChecksum: 0x" + check_sum + "[unverified]\n\t[Checksum Status: Unverified]"
	Message += "\n\tUDP payload (" + str(lenint_udp-octlu_udp) + " bytes)"
	udp_payload = lenint_udp-octlu_udp


	RES[T_ACTU].update(UDP = TREE_CHILDREN[T_ACTU].get("UDP")+Message+"\n\n")
	proto_udp1 = port_dst_int
	proto_udp2 = port_src_int
	M_tmp = ""
	if proto_udp1 == 67 or proto_udp2 == 67 :
		P_ACTU = "DHCP"
		taille_dhcp = udp_payload
		Message += 	"\n\nDynamic Host Configuration Protocol "
		L = etude_DHCP(lignes,i,nbcol2,nboct_lu)
		M_tmp += L[3]
		Message += L[4]
	elif proto_udp1 == 53 or proto_udp2 == 53 :
		P_ACTU = "DNS"
		taille_dns = udp_payload
		Message += 	"\n\n"
		L = etude_DNS(lignes,i,nbcol2,nboct_lu)
		Message += L
	else :
		print("Le protocole présent dans UDP n'est pas traité... Seuls DHCP et DNS le sont.")

	return Message + M_tmp

def etude_DHCP(lignes,i,nbcol2,nboct_lu):
	""" permet l'analyse DHCP puis appelle la fonction annalysant ses options """
	Message = ""
	octlu_DHCP = 0
	a_lire = nboct_lu + 1
	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	a_lire = a_lire + 1
	octlu_DHCP += 1
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	msg_type = L[3]
	msg_typeint = int(msg_type, 16)
	if msg_typeint == 1 :
		Message += "\n\tMessage type: Boot Request (1)\n\t"
	if msg_typeint == 2 :
		Message += "\n\tMessage type: Boot Reply (2)\n\t"

	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	a_lire = a_lire + 1
	octlu_DHCP += 1
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	Message += "Hardware type: Ethernet 0x" + L[3] +"\n\t"

	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	a_lire = a_lire + 1
	octlu_DHCP += 1
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	Message += "Hardware adress length: " + str(int(L[3],16)) + "\n\t"

	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	a_lire = a_lire + 4
	octlu_DHCP += 1
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	Message += "Hops: " + str(int(L[3],16)) + "\n\t"

	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	a_lire = a_lire + 2
	octlu_DHCP += 4
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	Message += "Transaction ID: 0x" + L[3] + "\n\t"

	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	a_lire = a_lire + 2
	octlu_DHCP += 2
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	Message += "Seconds elapsed: " + str(int(L[3],16)) + "\n\t"

	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	a_lire = a_lire + 4
	octlu_DHCP += 2
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	flag = bin(int(L[3],16))[2:].zfill(16)
	bit_15 = int(flag[0])

	if bit_15 == 0:
		tmp = flag[0] +"... .... .... .... = Broadcast flag: Unicast\n\t\t"
		c = "Bootp flags: 0x" + L[3] + " (Unicast)\n\t\t" + tmp
		c += "."
		cpt = 0
		for j in range (1, 16):
			if cpt == 3:
				c += " "+ flag[j]
				cpt = 0
			else :
				c += flag[j]
				cpt += 1
		c += " = Reserved flags: " + str(hex((int(flag[1:], 16))))
		Message += c + "\n\t"

	if bit_15 == 1:
		tmp = flag[0] +"... .... .... .... = Broadcast flag: Broadcast\n\t\t"
		c = "Bootp flags: 0x" + L[3] + " (Broadcast)\n\t\t" + tmp
		c += "."
		cpt = 0
		for j in range (1, 16):
			if cpt == 3:
				c += " "+ flag[j]
				cpt = 0
			else :
				c += flag[j]
				cpt += 1
		c += " = Reserved flags: " + str(hex((int(flag[1:], 16))))
		Message += c + "\n\t"


	L = lecture_octet(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	a_lire = a_lire + 4
	octlu_DHCP += 4
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	tmp = ''
	ip = ''
	for j in range (len(L[3])):
		if L[3][j] != ':':
			tmp += L[3][j]
		if L[3][j] == ':':
			actu = str(int(tmp, 16))
			ip += actu + '.'
			tmp = ''
		if j == len(L[3])-1:
			actu = str(int(tmp,16))
			ip += actu
			tmp = ''
	c = 'Client IP adress:  '+ ip +'\n'
	Message += c


	L = lecture_octet(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	a_lire = a_lire + 4
	octlu_DHCP += 4
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	tmp = ''
	ip = ''
	for j in range (len(L[3])):
		if L[3][j] != ':':
			tmp += L[3][j]
		if L[3][j] == ':':
			actu = str(int(tmp, 16))
			ip += actu + '.'
			tmp = ''
		if j == len(L[3])-1:
			actu = str(int(tmp,16))
			ip += actu
			tmp = ''
	c = '\tYour (client) IP adress:  '+ ip +'\n'
	Message += c


	L = lecture_octet(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	a_lire = a_lire + 4
	octlu_DHCP += 4
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	tmp = ''
	ip = ''
	for j in range (len(L[3])):
		if L[3][j] != ':':
			tmp += L[3][j]
		if L[3][j] == ':':
			actu = str(int(tmp, 16))
			ip += actu + '.'
			tmp = ''
		if j == len(L[3])-1:
			actu = str(int(tmp,16))
			ip += actu
			tmp = ''
	c = '\tNext server IP adress:  '+ ip +'\n'
	Message += c


	L = lecture_octet(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	a_lire = a_lire + 6
	octlu_DHCP += 4
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	tmp = ''
	ip = ''
	for j in range (len(L[3])):
		if L[3][j] != ':':
			tmp += L[3][j]
		if L[3][j] == ':':
			actu = str(int(tmp, 16))
			ip += actu + '.'
			tmp = ''
		if j == len(L[3])-1:
			actu = str(int(tmp,16))
			ip += actu
			tmp = ''
	c = '\tRelay agent IP adress:  '+ ip +'\n'
	Message += c


	L = lecture_octet(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	a_lire = a_lire + 10
	octlu_DHCP += 6
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	Message += "\tClient Mac adress: ("+L[3]+")\n\t"



	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	a_lire = a_lire + 64
	octlu_DHCP += 10
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	Message += "Client hardware adress padding: "+ L[3] +"\n\t"


	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	octlu_DHCP += 64
	a_lire = a_lire + 128
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	Message += "Server host name not given\n\t"


	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	octlu_DHCP += 128
	a_lire = a_lire + 4
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	Message += "Boot file name not given\n\t"

	option_len = octlu_DHCP

	L = option_DHCP(lignes,i,nbcol2,nboct_lu,a_lire,option_len)
	Message += L[0]
	prot = L[1]
	global T_ACTU, RES, TREE_CHILDREN
	TREE_CHILDREN[T_ACTU].update(DHCP = "Dynamic Host Configuration Protocol "+ prot.replace("\n",""))
	RES[T_ACTU].update(DHCP = "Dynamic Host Configuration Protocol "+ prot+Message)


	return [nboct_lu,i,nbcol2,Message,prot]

# return[Message, prot] avec prot le protocole utilisé (discover,ack...)
def option_DHCP(lignes,i,nbcol2,nboct_lu,a_lire,option_len):
	""" permet l'analyse de quelques option de DHCP """

	Message = ""

	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	Message += "Magic cookie: DHCP\n\t"
	opt_lu = 4


	a_lire = a_lire + 1
	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	option_type = int(L[3],16)
	prot = ""

	while option_type != 255 :
		if option_type not in (1,3,15,6,12,28,43,50,51,53,54,55,57,58,59,60,61,114,15, 116, 2, 224):
			print("l'option "+ str(option_type) +" n'a pas été configurée pour DHCP")
			return (Message, prot)

		if option_type == 224:
			Message += "\tOption: (224) Private\n"
			a_lire += 1 # pour lire length
			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += int(L[3],16)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			opt_lu += int(L[3],16) + 2
			Message += "\t\tLength: "+ str(int(L[3],16))+"\n\t\t"

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message +="Value: "+L[3]+"\n\n"

		if option_type == 2:
			Message += "\tOption: (2) Time Offset\n"
			a_lire += 1

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += int(L[3],16)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			opt_lu += int(L[3],16) + 2
			Message += "\t\tLength: "+ str(int(L[3],16))+"\n\t\t"

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message +="Time Offset: "+str(int(L[3],16))+"\n\n"

		if option_type == 116:
			Message += "\tOption: (116) DHCP Auto-Configuration\n"
			a_lire += 1

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += int(L[3],16)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			opt_lu += int(L[3],16) + 2
			Message += "\t\tLength: "+ str(int(L[3],16))+"\n\t\t"

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message +="DHCP Auto-Configuration: AutoConfigure (1)\n\n"

		if option_type == 1:
			Message += "\tOption : (1) Subnet Mask "
			a_lire += 1
			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += int(L[3],16)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			opt_lu += int(L[3],16) + 2
			c = "Length: "+ str(int(L[3],16))+"\n\t"

			L = lecture_octet(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			tmp = ''
			ip = ''
			for j in range (len(L[3])):
				if L[3][j] != ':':
					tmp += L[3][j]
				if L[3][j] == ':':
					actu = str(int(tmp, 16))
					ip += actu + '.'
					tmp = ''
				if j == len(L[3])-1:
					actu = str(int(tmp,16))
					ip += actu
					tmp = ''
			tmp += '\tSubnet Mask: ('+ ip +')\n\n'
			Message += "("+ip + ")\n\t\t" + c + tmp

		if option_type == 3:
			Message += "\tOption : (3) Router"
			a_lire += 1
			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += int(L[3],16)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			c = "Length: "+ str(int(L[3],16))+"\n\t"
			opt_lu += int(L[3],16) + 2
			L = lecture_octet(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			tmp = ''
			ip = ''
			for j in range (len(L[3])):
				if L[3][j] != ':':
					tmp += L[3][j]
				if L[3][j] == ':':
					actu = str(int(tmp, 16))
					ip += actu + '.'
					tmp = ''
				if j == len(L[3])-1:
					actu = str(int(tmp,16))
					ip += actu
					tmp = ''
			tmp += '\tRouter: '+ ip +'\n\n'
			Message += "\n\t\t" + c + tmp

		if option_type == 6:
			Message += "\tOption : (6) Domain Name Server"
			a_lire += 1
			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += int(L[3],16)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			opt_lu += int(L[3],16) + 2
			c = "Length: "+ str(int(L[3],16))+"\n\t"

			L = lecture_octet(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			tmp = ''
			ip = ''
			for j in range (len(L[3])):
				if L[3][j] != ':':
					tmp += L[3][j]
				if L[3][j] == ':':
					actu = str(int(tmp, 16))
					ip += actu + '.'
					tmp = ''
				if j == len(L[3])-1:
					actu = str(int(tmp,16))
					ip += actu
					tmp = ''
			tmp += '\tDomain Name Server: '+ ip +'\n\n'
			Message += "\n\t\t" + c + tmp

		if option_type == 12:
			Message += "\tOption : (12) Host Name\n"
			a_lire += 1
			L = lecture_octet(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += int(L[3],16)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message += "\t\tLength: "+ str(int(L[3],16))+"\n"
			opt_lu += int(L[3],16) + 2
			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message += "\t\tHost Name: " + bytes.fromhex(L[3]).decode() +"\n\n"

		if option_type == 28:
			Message += "\tOption : (28) Broadcast Address "
			a_lire += 1
			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += int(L[3],16)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			c = "Length: "+ str(int(L[3],16))+"\n\t"
			opt_lu += int(L[3],16) + 2
			L = lecture_octet(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			tmp = ''
			ip = ''
			for j in range (len(L[3])):
				if L[3][j] != ':':
					tmp += L[3][j]
				if L[3][j] == ':':
					actu = str(int(tmp, 16))
					ip += actu + '.'
					tmp = ''
				if j == len(L[3])-1:
					actu = str(int(tmp,16))
					ip += actu
					tmp = ''
			tmp += '\tBroadcast Address: '+ ip +'\n\n'
			Message += "("+ip + ")\n\t\t" + c + tmp

		if option_type == 43:
			Message += "\tOption: (42) Vendor-Specific Information\n"
			a_lire += 1

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += int(L[3],16)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			opt_lu += int(L[3],16) + 2
			Message += "\t\tLength: "+ str(int(L[3],16))+"\n\t\t"

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message +="Vendor-Specific Information : " + L[3] + "\n\n"

		if option_type == 50:
			Message += "\tOption: (50) Requested IP Adress "
			a_lire += 1

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += int(L[3],16)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			c = "Length: "+ str(int(L[3],16))+"\n\t"

			L = lecture_octet(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			tmp = ''
			ip = ''
			for j in range (len(L[3])):
				if L[3][j] != ':':
					tmp += L[3][j]
				if L[3][j] == ':':
					actu = str(int(tmp, 16))
					ip += actu + '.'
					tmp = ''
				if j == len(L[3])-1:
					actu = str(int(tmp,16))
					ip += actu
					tmp = ''
			tmp += '\tRequested IP Address: '+ ip +'\n'
			Message += ip + "\n\t\t" + c + tmp + "\n"

		if option_type == 51:
			Message += "\tOption: (51) IP Address Lease Time\n"
			a_lire += 1

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += int(L[3],16)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			opt_lu += int(L[3],16) + 2
			Message += "\t\tLength: "+ str(int(L[3],16))+"\n\t\t"

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message +="IP Address Lease Time : (" + str(int(L[3],16)) + "s)\n\n"

		if option_type == 53:
			Message += "Option : (53) DHCP Message Type "
			a_lire += 1
			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += int(L[3],16)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			opt_lu += int(L[3],16) + 2
			c = "\tLength: "+ str(int(L[3],16))+"\n\t"

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			c += "\tDHCP: "
			int_opt = int(L[3], 16)
			global TREE_CHILDREN, T_ACTU

			if int_opt == 1: #discover
				c+= "(Discover) "+ str(int_opt)
				Message += "(Discover)\n\t"+ c + "\n"
				prot = "(Discover)"

			if int_opt == 2: #offer
				c+= "(Offer) "+ str(int_opt)
				Message += "(Offer)\n\t"+ c + "\n"
				prot = "(Offer)"

			if int_opt == 3: #Request
				c+= "(Request) "+ str(int_opt)
				Message += "(Request)\n\t"+ c + "\n"
				prot = "(Request)"

			if int_opt == 4: #Decline
				c+= "(Decline) "+ str(int_opt)
				Message += "(Decline)\n\t"+ c + "\n"
				prot = "(Decline)"

			if int_opt == 5: #ACK
				c+= "(ACK) "+ str(int_opt)
				Message += "(ACK)\n\t"+ c + "\n"
				prot = "(ACK)"

			if int_opt == 6: #NAK
				c+= "(NAK) "+ str(int_opt)
				Message += "(NAK)\n\t"+ c + "\n"
				prot = "(NAK)"

			if int_opt == 7: #Release
				c+= "(Release) "+ str(int_opt)
				Message += "(Release)\n\t"+ c + "\n"
				prot = "(Release)"

			if int_opt == 8: #INFORM
				c+= "(Inform) "+ str(int_opt)
				Message += "(Inform)\n\t"+ c + "\n"
				prot = "(Inform)"
			Message += "\n"

		if option_type == 54:
			Message += "\tOption: (54) DHCP Server Identifier "
			a_lire += 1

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += int(L[3],16)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			c = "Length: "+ str(int(L[3],16))+"\n\t"
			opt_lu += int(L[3],16) + 2

			L = lecture_octet(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			tmp = ''
			ip = ''
			for j in range (len(L[3])):
				if L[3][j] != ':':
					tmp += L[3][j]
				if L[3][j] == ':':
					actu = str(int(tmp, 16))
					ip += actu + '.'
					tmp = ''
				if j == len(L[3])-1:
					actu = str(int(tmp,16))
					ip += actu
					tmp = ''
			tmp += '\tDHCP Server Identifier: '+ ip +'\n'
			Message += ip + "\n\t\t" + c + tmp +"\n"

		if option_type == 55:
			Message += "\tOption: (55) Parameter Request List\n\t\t"
			a_lire += 1
			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += 1
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message += "Length: "+ str(int(L[3],16))+"\n"
			to_read = int(L[3],16)
			opt_lu += int(L[3],16) + 2
			for j in range(0, to_read):
				if j == to_read-1:
					L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
					i = L[0]
					nbcol2 = L[1]
					nboct_lu = L[2]
					Message += "\t\tParameter Request List Item: ("+ str(int(L[3],16)) +")\n"
					continue
				L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				a_lire += 1
				i = L[0]
				nbcol2 = L[1]
				nboct_lu = L[2]
				Message += "\t\tParameter Request List Item: ("+ str(int(L[3],16)) +")\n"
			Message += "\n"

		if option_type == 57:
			Message += "\tOption : (57) Maximum DHCP Message Size\n"
			a_lire += 1
			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += int(L[3],16)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			opt_lu += int(L[3],16) + 2
			Message += "\t\tLength: "+ str(int(L[3],16))+"\n"

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message += "\t\tMaximum DHCP Message Size: " + str(int(L[3],16)) + "\n\n"

		if option_type == 58:
			Message += "\tOption: (58) Renewal Time Value"
			a_lire += 1

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += int(L[3],16)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			c = "\t\tLength: "+ str(int(L[3],16))
			opt_lu += int(L[3],16) + 2

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message += "\n\t\tRenewal Time Value: ("+ str(int(L[3],16))+"s)\n\n"

		if option_type == 59:
			Message += "\tOption: (59) Rebinding Time Value"
			a_lire += 1

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += int(L[3],16)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			c = "\t\tLength: "+ str(int(L[3],16))
			opt_lu += int(L[3],16) + 2
			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message += "\n\t\tRebinding Time Value: ("+ str(int(L[3],16))+"s)\n\n"

		if option_type == 60:
			Message += "\tOption: (60) Vendor class identifier"
			a_lire += 1

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += int(L[3],16)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message += "\t\tLength: "+ str(int(L[3],16))
			opt_lu += int(L[3],16) + 2
			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message += "\n\t\tVendor class identifier: "+ bytes.fromhex(L[3]).decode()+"\n\n"

		if option_type == 61:
			Message += "\tOption : (61) Client identifier\n"
			a_lire += 1

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += 1
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			opt_lu += int(L[3],16) + 2
			Message += "\t\tLength: "+ str(int(L[3],16))+"\n"

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += 6
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message += "\t\tHardware type: Ethernet (0x01)\n"

			L = lecture_octet(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message += "\t\tClient Mac address: (" + L[3] + ")\n\n"

		if option_type == 114:
			Message += "\tOption: (114) DHCP Captive-Portal\n"
			a_lire += 1
			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			opt_lu += int(L[3],16) + 2
			a_lire += 1
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message += "\t\tLength: "+ str(int(L[3],16))+"\n\t\tCaptive Portal: "
			tmp = ""
			to_readlen = int(L[3],16)

			for j in range (0, to_readlen):
				L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				i = L[0]
				nbcol2 = L[1]
				nboct_lu = L[2]

				if int(L[3],16) <= 31:
					tmp += "."
					a_lire += 1
					continue
				try:
					tmp += bytes.fromhex(L[3]).decode()
					a_lire += 1
				except ValueError:
					a_lire +=1
					break
			Message += tmp.replace("\n","") + "\n\n"
			a_lire -= 1

		if option_type == 15:
			Message += "\tOption: (15) Domain Name\n"
			a_lire += 1
			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += int(L[3],16)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message += "\t\tLength: "+ str(int(L[3],16))
			opt_lu += int(L[3],16) + 2
			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message += "\n\t\tDomain Name: "+ bytes.fromhex(L[3]).decode()+"\n\n"

		a_lire += 1
		L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
		i = L[0]
		nbcol2 = L[1]
		nboct_lu = L[2]
		option_type = int(L[3],16)

	if option_type == 255:
		opt_lu += 1
		Message += "\tOption: (255) End\n"
		Message += "\t\tOption End: "+ str(int(L[3],16))+"\n\n"
	global taille_dhcp

	if taille_dhcp > 300 :

		return [Message, prot]
	a_lire += 300 - (opt_lu+option_len)
	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	Message += "\tPadding: "+L[3]

	return [Message, prot]

# return Message
def etude_DNS(lignes,i,nbcol2,nboct_lu):
	MSG_debut = "Domain Name System "
	Message = ""
	octlu_DNS = 0
	a_lire = nboct_lu + 2
	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	## pour la compression
	I_DNS = i
	NBCOL2_DNS = nbcol2
	NBOCT_LU_DNS = nboct_lu

	octlu_DNS += 2
	a_lire += 2
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	Message += "\tTransaction ID: " + str(hex(int(L[3],16))) + "\n"

	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	octlu_DNS += 2
	a_lire += 2
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	binaire = bin(int(L[3],16)).zfill(16)
	Message += "\tFlags: " + str(hex(int(L[3],16)))

	reponse = False
	global TREE_CHILDREN, T_ACTU, RES

	if binaire[2] == '1':
		reponse = True
		stock = ""
		MSG_debut += "(response)\n"
		TREE_CHILDREN[T_ACTU].update(DNS= MSG_debut.replace("\n",""))
		MSG_debut += Message
		Message = MSG_debut
		stock = binaire[3]+binaire[4]+binaire[5]+binaire[6]
		tmp = int(stock,2)
		if tmp == 0:
			Message += "Standard query response\n"

		if tmp == 1:
			Message += "Requête inverse (IQuery)\n"

		if tmp == 2:
			Message += "Statut du serveur (Status)\n"

	if binaire[2] == '0':
		stock = ""
		MSG_debut += "(query)\n"
		TREE_CHILDREN[T_ACTU].update(DNS= MSG_debut.replace("\n",""))
		MSG_debut += Message
		Message = MSG_debut
		Message += " Standard query\n"

	nb_quest = 0
	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	octlu_DNS += 2
	a_lire += 2
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	Message += "\tQuestions: " + str(int(L[3],16)) + "\n"
	nb_quest = int(L[3],16)

	nb_anws = 0
	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	octlu_DNS += 2
	a_lire += 2
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	Message += "\tAnswer RRs: " + str(int(L[3],16)) + "\n"
	nb_anws = str(int(L[3],16))

	nb_auth = 0
	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	octlu_DNS += 2
	a_lire += 2
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	Message += "\tAuthority RRs: " + str(int(L[3],16)) + "\n"
	nb_auth = int(L[3],16)

	nb_addit = 0
	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	octlu_DNS += 2
	a_lire += 1
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	Message += "\tAdditional RRs: " + str(int(L[3],16)) + "\n"
	nb_addit = int(L[3],16)

	Message += "\n\tQueries\n"
	Message_tmp = ""

	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	octlu_DNS += 1
	a_lire += 1
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	name_msg = ""

	while L[3] != "00":
		L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
		octlu_DNS += 1
		a_lire += 1
		i = L[0]
		nbcol2 = L[1]
		nboct_lu = L[2]
		if L[3] == "00":
			break
		if int(L[3],16) < 20:
			name_msg += '.'
			continue
		name_msg += bytes.fromhex(L[3]).decode()

	new_name_msg = name_msg.replace("\n", "")
	name_msg = new_name_msg

	Message += "\t\t"+name_msg+": "
	Message_tmp += "\t\t\tName: " + name_msg + "\n"

	MSG_TO_KEEP = ""
	for j in range (0, len(name_msg)):
		if name_msg[j] != '.':
			continue
		MSG_TO_KEEP = name_msg[j:]
		break

	a_lire += 1
	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	octlu_DNS += 2
	a_lire += 2
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]


	to_add_quer = "type "
	type_int = int((L[3]), 16)

	if type_int == 1:
		Message_tmp += "\t\t\tType: A (Host Address) (1)\n"
		to_add_quer += "A,"

	if type_int == 65:
		Message_tmp += "\t\t\tType: HTTPS (HTTPS Specitic Service Endpoints) (65)\n"
		to_add_quer += "HTTPS, "

	if type_int == 5:
		Message_tmp += "\t\t\tType: CNAME (Canonical Name for an alias) (05)\n"
		to_add_quer += "CNAME, "

	if type_int == 2:
		Message_tmp += "\t\t\tType : NS (Authoritative Server In Charge Of A Domain name) (02)\n"
		to_add_quer += "NS, "

	if type_int == 15:
		Message_tmp += "\t\t\tType : MX (Name Of The Incoming Mail Server For A Domain) (15)\n"
		to_add_quer += "MX, "

	if type_int == 28:
		Message_tmp += "\t\t\tType : AAAA (IPv6 Address Corresponding To A Domain Name) (28)\n"
		to_add_quer += "AAAA, "

	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	octlu_DNS += 2
	a_lire += 2
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	classe_int = int(L[3], 16)

	if classe_int == 1 :
		Message_tmp += "\t\t\tClass : IN (0x0001)\n"
		to_add_quer += "class IN\n"

	if classe_int == 2 :
		Message_tmp += "\t\t\tClass : CS (0x0002)\n"
		to_add_quer += "class CS\n"

	if classe_int == 3 :
		Message_tmp += "\t\t\tClass : CH (0x0003)\n"
		to_add_quer += "class CH\n"

	if classe_int == 4 :
		Message_tmp += "\t\t\tClass : HS (0x0004)\n"
		to_add_quer += "class HS\n"

	Message += to_add_quer + Message_tmp

	if nb_auth == 0 and nb_addit == 0 and nb_anws == 0:
		return ("DNS", Message)

	if int(nb_anws) > 0 :
		Message += "\n\tAnswers\n"
		for j in range(0, int(nb_anws)):
			Message_tmp = ""
			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			octlu_DNS += 2
			a_lire += 2
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			name_pointeur = int((L[3])[2:],16)
			name_str = det_compressed(lignes, I_DNS, NBCOL2_DNS, NBOCT_LU_DNS, name_pointeur)
			to_add_quer = "\t\t" + name_str.replace("\n","") + ": "
			Message_tmp += "\n\t\t\tName: " + name_str.replace("\n","") + "\n"

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			octlu_DNS += 2
			a_lire += 2
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]

			type_int = int((L[3]), 16)

			if type_int == 1:
				Message_tmp += "\t\t\tType: A (Host Address) (1)\n"
				to_add_quer += "type: A,"

			if type_int == 65:
				Message_tmp += "\t\t\tType: HTTPS (HTTPS Specitic Service Endpoints) (65)\n"
				to_add_quer += "type: HTTPS, "

			if type_int == 5:
				Message_tmp += "\t\t\tType: CNAME (Canonical Name for an alias) (05)\n"
				to_add_quer += "type: CNAME, "

			if type_int == 2:
				Message_tmp += "\t\t\tType : NS (Authoritative Server In Charge Of A Domain name) (02)\n"
				to_add_quer += "type: NS, "

			if type_int == 15:
				Message_tmp += "\t\t\tType : MX (Name Of The Incoming Mail Server For A Domain) (15)\n"
				to_add_quer += "type: MX, "

			if type_int == 28:
				Message_tmp += "\t\t\tType : AAAA (IPv6 Address Corresponding To A Domain Name) (28)\n"
				to_add_quer += "type: AAAA, "

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			octlu_DNS += 2
			a_lire += 4
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			classe_int = int(L[3], 16)

			if classe_int == 1 :
				Message_tmp += "\t\t\tClass : IN (0x0001)\n"
				to_add_quer += "class IN"

			if classe_int == 2 :
				Message_tmp += "\t\t\tClass : CS (0x0002)\n"
				to_add_quer += "class CS"

			if classe_int == 3 :
				Message_tmp += "\t\t\tClass : CH (0x0003)\n"
				to_add_quer += "class CH"

			if classe_int == 4 :
				Message_tmp += "\t\t\tClass : HS (0x0004)\n"
				to_add_quer += "class HS"

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			octlu_DNS += 4
			a_lire += 2
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message_tmp += "\t\t\tTime To Live: " + str(int(L[3], 16))+"\n"

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			octlu_DNS += 2
			a_lire += 1
			save = a_lire
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message_tmp += "\t\t\tData length: " + str(int(L[3], 16)) +"\n"
			to_readlen = int(L[3], 16)

			if type_int == 1:
				a_lire += 3
				L = lecture_octet(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				octlu_DNS += 4
				a_lire += 2
				i = L[0]
				nbcol2 = L[1]
				nboct_lu = L[2]
				tmp = ''
				ip = ''

				for j in range (len(L[3])):
					if L[3][j] != ':':
						tmp += L[3][j]
					if L[3][j] == ':':
						actu = str(int(tmp, 16))
						ip += actu + '.'
						tmp = ''
					if j == len(L[3])-1:
						actu = str(int(tmp,16))
						ip += actu
						tmp = ''
				Message_tmp += "\t\t\tAddress: " + ip + "\n"
				to_add_quer += ", addr " + ip

			if type_int == 5:
				tmp = ""
				L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				octlu_DNS += 1
				a_lire += 1
				i = L[0]
				nbcol2 = L[1]
				nboct_lu = L[2]
				for j in range (1, to_readlen):
					L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
					octlu_DNS += 1
					i = L[0]
					nbcol2 = L[1]
					nboct_lu = L[2]
					if j == to_readlen-1:
						a_lire += 2
						break
					if int(L[3],16) <= 31:
						tmp += "."
						a_lire += 1
						continue
					try:
						tmp += bytes.fromhex(L[3]).decode()
						a_lire += 1
					except ValueError:
						a_lire +=1
						L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
						octlu_DNS += 1
						i = L[0]
						nbcol2 = L[1]
						nboct_lu = L[2]
						tmp_msg = ''
						name_pointeur = int(L[3], 16)
						tmp_msg += det_compressed(lignes, I_DNS, NBCOL2_DNS, NBOCT_LU_DNS, name_pointeur)
						tmp += '.' + tmp_msg
						a_lire += 2
						break
				Message_tmp += "\t\t\tCNAME: " + tmp.replace("\n", "") + "\n"
				to_add_quer += ", cname " + tmp.replace("\n", "")
			Message += to_add_quer + Message_tmp

	if int(nb_auth) > 0:
		Message += "\n\tAuthoritative nameservers\n"
		for j in range(0, int(nb_auth)):
			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			octlu_DNS += 2
			a_lire += 2
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			name_pointeur = int((L[3])[2:],16)
			name_str = det_compressed(lignes, I_DNS, NBCOL2_DNS, NBOCT_LU_DNS, name_pointeur)
			nom_auth = name_str

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			octlu_DNS += 2
			a_lire += 2
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]

			if L[3] == "0006":
				to_add_quer = "\t\t" + nom_auth + ": type SOA, "
				Message_tmp = ""
				Message_tmp += "\t\t\tName: " + nom_auth + "\n"
				Message_tmp += "\t\t\tType: SOA (Start Of a zone of Authority) (6)\n"
				L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				octlu_DNS += 2
				a_lire += 4
				i = L[0]
				nbcol2 = L[1]
				nboct_lu = L[2]
				classe_int = int(L[3], 16)

				if classe_int == 1 :
					Message_tmp += "\t\t\tClass : IN (0x0001)\n"
					to_add_quer += "class IN, "

				if classe_int == 2 :
					Message_tmp += "\t\t\tClass : CS (0x0002)\n"
					to_add_quer += "class CS, "

				if classe_int == 3 :
					Message_tmp += "\t\t\tClass : CH (0x0003)\n"
					to_add_quer += "class CH, "

				if classe_int == 4 :
					Message_tmp += "\t\t\tClass : HS (0x0004)\n"
					to_add_quer += "class HS, "

				L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				octlu_DNS += 4
				a_lire += 2
				i = L[0]
				nbcol2 = L[1]
				nboct_lu = L[2]
				Message_tmp += "\t\t\tTime To Live: " + str(int(L[3], 16))+"\n"

				L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				octlu_DNS += 2
				a_lire += 1
				i = L[0]
				nbcol2 = L[1]
				nboct_lu = L[2]

				Message_tmp += "\t\t\tData length: " + str(int(L[3], 16)) +"\n"
				to_readlen = int(L[3],16)
				count = 0
				tmp = ""
				L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				octlu_DNS += 1
				a_lire += 1
				i = L[0]
				nbcol2 = L[1]
				nboct_lu = L[2]
				count += 1
				for j in range (0, to_readlen):
					L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
					octlu_DNS += 1
					count += 1
					i = L[0]
					nbcol2 = L[1]
					nboct_lu = L[2]
					if j == to_readlen-1:
						a_lire += 1
						break
					if L[3] == "00":
						a_lire += 1
						break
					if int(L[3],16) <= 31:
						tmp += "."
						a_lire += 1
						continue
					try:
						tmp += bytes.fromhex(L[3]).decode()
						a_lire += 1
					except ValueError:
						a_lire +=1
						L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
						count += 1
						octlu_DNS += 1
						i = L[0]
						nbcol2 = L[1]
						nboct_lu = L[2]
						a_lire += 1
						tmp_msg = ''
						name_pointeur = int(L[3], 16)
						tmp_msg += det_compressed(lignes, I_DNS, NBCOL2_DNS, NBOCT_LU_DNS, name_pointeur)
						tmp += '.' + tmp_msg

						break
				Message_tmp += "\t\t\tPrimary name server: "+ tmp+"\n"
				to_add_quer += "mname "+tmp
				tmp = ""
				len_max = (to_readlen - (count+20))

				L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				octlu_DNS += 1
				a_lire += 1
				i = L[0]
				nbcol2 = L[1]
				nboct_lu = L[2]

				for j in range (1, to_readlen):
					L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
					octlu_DNS += 1
					count += 1
					i = L[0]
					nbcol2 = L[1]
					nboct_lu = L[2]
					if L[3] == "00":
						a_lire += 4
						break
					if j == to_readlen-1:
						a_lire += 4
						break
					if int(L[3],16) <= 31:
						tmp += "."
						a_lire += 1
						continue
					try:
						tmp += bytes.fromhex(L[3]).decode()
						a_lire += 1
					except ValueError:
						a_lire += 1
						L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
						octlu_DNS += 1
						count += 1
						i = L[0]
						nbcol2 = L[1]
						nboct_lu = L[2]
						a_lire += 4

						tmp_msg = ''
						name_pointeur = int(L[3], 16)
						tmp_msg += det_compressed(lignes, I_DNS, NBCOL2_DNS, NBOCT_LU_DNS, name_pointeur)
						tmp += '.' + tmp_msg
						break

				Message_tmp +="\t\t\tResponsible authority's mailbox: " + tmp.replace("\n","") + "\n"
				to_add_quer += "\n"
				L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				octlu_DNS += 4
				a_lire += 4
				i = L[0]
				nbcol2 = L[1]
				nboct_lu = L[2]
				Message_tmp += "\t\t\tSerial Number: " + str(int(L[3],16)) + "\n"
				L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				octlu_DNS += 4
				a_lire += 4
				i = L[0]
				nbcol2 = L[1]
				nboct_lu = L[2]
				Message_tmp += "\t\t\tRefresh Interval: " + str(int(L[3],16)) + "\n"

				L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				octlu_DNS += 4
				a_lire += 4
				i = L[0]
				nbcol2 = L[1]
				nboct_lu = L[2]
				Message_tmp += "\t\t\tRetry Interval: " + str(int(L[3],16)) + "\n"

				L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				octlu_DNS += 4
				a_lire += 4
				i = L[0]
				nbcol2 = L[1]
				nboct_lu = L[2]
				Message_tmp += "\t\t\tExpire limit: " + str(int(L[3],16)) + "\n"

				L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				octlu_DNS += 4
				a_lire += 2
				i = L[0]
				nbcol2 = L[1]
				nboct_lu = L[2]
				Message_tmp += "\t\t\tMinimum TTL: " + str(int(L[3],16)) + "\n"
				Message += to_add_quer + Message_tmp

			if L[3] == "0002":
				to_add_quer = "\t\t" + nom_auth + ", type NS, "
				Message_tmp = ""
				Message_tmp += "\t\t\tName: " + nom_auth + "\n"
				Message_tmp += "\t\t\tType: NS (authoritative Name Server) (2)\n"

				L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				octlu_DNS += 2
				a_lire += 4
				i = L[0]
				nbcol2 = L[1]
				nboct_lu = L[2]
				classe_int = int(L[3], 16)

				if classe_int == 1 :
					Message_tmp += "\t\t\tClass : IN (0x0001)\n"
					to_add_quer += "class IN, "

				if classe_int == 2 :
					Message_tmp += "\t\t\tClass : CS (0x0002)\n"
					to_add_quer += "class CS, "

				if classe_int == 3 :
					Message_tmp += "\t\t\tClass : CH (0x0003)\n"
					to_add_quer += "class CH, "

				if classe_int == 4 :
					Message_tmp += "\t\t\tClass : HS (0x0004)\n"
					to_add_quer += "class HS, "

				L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				octlu_DNS += 4
				a_lire += 2
				i = L[0]
				nbcol2 = L[1]
				nboct_lu = L[2]
				Message_tmp += "\t\t\tTime To Live: " + str(int(L[3], 16))+"\n"

				L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				octlu_DNS += 2
				a_lire += 1
				i = L[0]
				nbcol2 = L[1]
				nboct_lu = L[2]

				Message_tmp += "\t\t\tData length: " + str(int(L[3], 16)) +"\n"
				to_readlen = int(L[3],16)
				count = 0
				tmp = ""
				L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				octlu_DNS += 1
				a_lire += 1
				i = L[0]
				nbcol2 = L[1]
				nboct_lu = L[2]
				count += 1

				for j in range (0, to_readlen):
					L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
					count += 1
					i = L[0]
					nbcol2 = L[1]
					nboct_lu = L[2]
					if j == to_readlen-1:
						a_lire += 1
						break
					if L[3] == "00":
						a_lire += 1
						break
					if int(L[3],16) <= 31:
						tmp += "."
						a_lire += 1
						continue
					try:
						tmp += bytes.fromhex(L[3]).decode()
						a_lire += 1
					except ValueError:
						a_lire += 1
						L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
						octlu_DNS += 1
						count += 1
						i = L[0]
						nbcol2 = L[1]
						nboct_lu = L[2]
						a_lire += 1

						tmp_msg = ''
						name_pointeur = int(L[3], 16)
						tmp_msg += det_compressed(lignes, I_DNS, NBCOL2_DNS, NBOCT_LU_DNS, name_pointeur)
						tmp += '.' + tmp_msg
						break

				Message_tmp += "\t\t\tName Server: "+ tmp+"\n"
				to_add_quer += "ns "+tmp +"\n"
				Message += to_add_quer + Message_tmp
				a_lire += 1

	if int(nb_addit) > 0 :
		Message += "\n\tAdditional records\n"
		for x in range(0, int(nb_addit)):
			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			octlu_DNS += 2
			a_lire += 2
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			type_int = int(L[3], 16)
			name_pointeur = int((L[3])[1:],16)
			name_str = det_compressed(lignes, I_DNS, NBCOL2_DNS, NBOCT_LU_DNS, name_pointeur)
			nom_auth = name_str
			to_add_quer = "\t\t"+nom_auth+": "
			Message_tmp = "\t\t\tName: "+nom_auth + "\n"

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			octlu_DNS += 2
			a_lire += 2
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			type_int = int(L[3], 16)

			if type_int == 1:
				Message_tmp += "\t\t\tType: A (Host Address) (1)\n"
				to_add_quer += "type A, "

			if type_int == 28:
				Message_tmp += "\t\t\tType: AAAA (IPv6 Address) (28)\n"
				to_add_quer += "type AAAA, "


			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			octlu_DNS += 2
			a_lire += 4
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]

			classe_int = int(L[3], 16)

			if classe_int == 1 :
				Message_tmp += "\t\t\tClass : IN (0x0001)\n"
				to_add_quer += "class IN, "

			if classe_int == 2 :
				Message_tmp += "\t\t\tClass : CS (0x0002)\n"
				to_add_quer += "class CS, "

			if classe_int == 3 :
				Message_tmp += "\t\t\tClass : CH (0x0003)\n"
				to_add_quer += "class CH, "

			if classe_int == 4 :
				Message_tmp += "\t\t\tClass : HS (0x0004)\n"
				to_add_quer += "class HS, "

			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			octlu_DNS += 4
			a_lire += 2
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			Message_tmp += "\t\t\tTime To Live: " + str(int(L[3], 16))+"\n"
			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			Message_tmp += "\t\t\tData length: " + str(int(L[3], 16)) +"\n"
			octlu_DNS += 2
			a_lire += int(L[3], 16)
			tmp_ludns = int(L[3], 16)
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]

			if type_int == 1:
				L = lecture_octet(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				octlu_DNS += tmp_ludns
				a_lire += 2
				i = L[0]
				nbcol2 = L[1]
				nboct_lu = L[2]
				tmp = ''
				ip = ''
				for j in range (len(L[3])):
					if L[3][j] != ':':
						tmp += L[3][j]
					if L[3][j] == ':':
						actu = str(int(tmp, 16))
						ip += actu + '.'
						tmp = ''
					if j == len(L[3])-1:
						actu = str(int(tmp,16))
						ip += actu
				Message_tmp += "\t\t\tAddress: "+ ip+"\n"
				to_add_quer += "addr "+ ip +"\n"
				Message += to_add_quer + Message_tmp

			if type_int == 28:
				L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				octlu_DNS += tmp_ludns
				a_lire += 2
				i = L[0]
				nbcol2 = L[1]
				nboct_lu = L[2]
				tmp = ""
				count = 1
				cpt = 1
				maxi = len(L[3])
				for j in L[3]:
					if count == 4:
						if cpt != maxi:
							tmp += j + ":"
							count = 1
							cpt += 1
							continue
						else :
							tmp += j
							count +=1
							cpt += 1
							continue
					tmp += j
					count +=1
					cpt += 1
				Message_tmp += "\t\t\tAAAA Address: "+ tmp + "\n"
				to_add_quer += "addr "+ tmp +"\n"
				Message += to_add_quer + Message_tmp

	RES[T_ACTU].update(DNS = Message)
	return Message

def det_compressed(lignes, i, nbcol2, nboct_lu, name_p):
	i_st = i
	nbcol2_st = nbcol2
	nboct_lu_st = nboct_lu

	a_lire = nboct_lu + name_p
	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	a_lire += 1
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
	a_lire += 1
	i = L[0]
	nbcol2 = L[1]
	nboct_lu = L[2]
	name_msg = ""
	if int(L[3][0],16) > 11:
		L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
		a_lire += 1
		i = L[0]
		nbcol2 = L[1]
		nboct_lu = L[2]
		name_pointeur = int(L[3], 16)
		return det_compressed(lignes, i_st, nbcol2_st, nboct_lu_st, name_pointeur)

	else:
		if int(L[3], 16) >= 20:
			name_msg += L[3]
		while L[3] != "00":
			L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
			a_lire += 1
			i = L[0]
			nbcol2 = L[1]
			nboct_lu = L[2]
			if L[3] == "00":
				break
			if int(L[3],16) < 32:
				name_msg += '.'
				continue
			try:
				name_msg += bytes.fromhex(L[3]).decode()
			except ValueError:
				tmp_msg = ''
				L = lecture_octet2(lignes,i,nbcol2,nboct_lu,a_lire,nboct_lu)
				name_pointeur = int(L[3], 16)
				tmp_msg += det_compressed(lignes, i_st, nbcol2_st, nboct_lu_st, name_pointeur)
				name_msg += '.' + tmp_msg
				break
	return name_msg




def program(file=""):
	execution(file)


execution("")

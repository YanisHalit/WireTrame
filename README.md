WireTrame est un analyseur de protocoles réseau offline.

Deux versions de codes sont proposés, la première fonctionnant totalement avec l'interface graphique "WireTrame.py" la deuxième sans "WireTrame_backup.py".

Le dossier WireTrame est composé de:
		dossier ressources
		CodeSource.py
		HOWTO.md
		makefile
		README.md
		Résultats.txt (contiendra le résultat d'analyse d'une trace en passant par l'altérnative sans interface graphique )
		WireTrame.py
		WireTrame_backup.py

####### Ne sourtout pas supprimer le dossier ressources auquel cas le code ne pourra être fonctionnel #######


 -----------------
|STRUCTURE DU CODE|
 -----------------

Le dossier ressources contient certains fichiers nécessaire au bon fonctionnement de l'interface graphique du programme notamment le fichier "NePasToucher.txt" permettant de stocker temporairement les inputs utilisateurs afin de les analyser par la suite

	Variables et arguments de fonctions à connaître:
		#lignes = liste ou chaque élément représente une ligne du fichier contenant la/les traces fournies
		#i = ligne-1 traitée actuellement ( élément dans la liste )
		#col = numéro du caractère lu ( son emplacement dans l'élément de la liste )
		#nboct_lu = nombre d'octet déjà lus
		#nb_alire = nombre d'octet total qu'on veut lire en comptabilisant le nombre d'octets déjà lus
		#nblu_oblig = nombre d'octets qui doivent obligatoirement êtres lus avant de lire les octets suivant
		#IHL = taille séquence IP
		#option_len = taille de DHCP sans options

 	 -----------------
	|Fonctions outils|
 	 -----------------

		*lecture_fichier(file) :
					-Lecture de tout le fichier file, renvoyant une liste où chaque element de la liste est une ligne de notre fichier
					-Deviens "lecture_fichier(file='')" dans la version terminal ainsi si la fonction est passé sans paramètre il sera demandé à l'utilisateur d'entrer le chemin vers le fichier qu'il souhaite lire.

		*lecture_octet(lignes, i, col, nboct_lu, nboct_alire, nblu_oblig):
					-Lit (nboct_alire-nblu_oblig) octets situés en ligne i à partir de la position col sur la ligne et retourne les caractères lus si se sont des octets ou des offsets, tel que les octets sont séparés par le caractère ':'.

		*lecture_octet2(lignes, i, col, nboct_lu, nboct_alire, nblu_oblig):
					-Même fonctionnement que lecture_octet mais cette fois la séparation se fait avec espaces.

		*is_offset(lignes,i,col2) 
					-Détermine si le début de ligne est un offset.

		*is_octet(lignes,i,col2) 
					-Détermine si les caractères lus sont un octet.

		*det_offset(lignes,i,col2) 
					-Retourne l'offset de la ligne i s'il existe.

		*def reset() 
					-Réinitialise certaines variables globales nécessaires pour la gestion de l'interface graphique.

		*def reset_list() 
					-Réinitialise certaines variable globales (les listes) nécessaires pour l'interface graphique (treeview) lors du passage d'une trame à une autre.

		*program(file=""):
					-Appelé par le code Wiretrame.py ayant récuperé le fichier que l'on souhaite analyser

 	 -------------------
	|Fonctions d'analyse|
	 -------------------

		*lecture_Ethernet(lignes, li, nboct_lu):
					-Analyse le début de la trame (sequence Ethernet) et détermine dans un premier temps si le protocole est IP ( les autres protocoles n'étant pas pris en charge ).
					-Renvoie l'analyse d'UNE trame entière sous forme d'une chaine de caractère en appelant lecture_IP, la taille totale de la trace ainsi que le [(n° de lignes à traiter)-1] dans la suite.

		*lecture_IP(lignes, li, nbcol, nboct_l):
		 			-Analyse la sequence IP et appelle "etude_option_ip" si des options sont présentes (IHL > 20) une erreur est soulevée si IHL < 20.
					Vérifie que le champ protocole correspond à UDP afin d'appeler la fonction "etude_UDP".

		*etude_UDP(lignes,i,nbcol2,nboct_lu) 
					-Analyse la séquence UDP si elle existe, et appellela fonction etude_DHCP ou etude_DNS selon le numéro de port.

		*etude_DHCP(lignes,i,nbcol2,nboct_lu):
					-Analyse le protocole DHCP et appelle la fonction etude_option_DHCP, 22 options sont traitées.

		*etude_DNS(lignes,i,nbcol2,nboct_lu):
					-Analyse de l'application DNS en effectuant la décompréssions des noms

		*execution(fichier):
					-Lance l'analyse des trames présentes dans le fichier "fichier" qui sera passé par la fonction program

		###WireTrame.py###
demarrage(): -> interface(): --> 
		###CodeSource.py###
-->  program(..): --> excution(..): --->
	--->  lecture_ethernet(..) ---> lecture_IP(...): ---->  
									----> etude_udp(...) : ----->
										-----> analyse_dns(..)
										-----> analyse_dhcp(..)




Copyright (C)
=============

  - 2021-2022 HALIT Yanis, KORRABI Madjid (WireTrame)
          under Python license (cf. `LICENSE.python`).

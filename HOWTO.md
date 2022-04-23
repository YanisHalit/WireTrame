
### INSTALLATIONS ET USAGES DE WireTrame:

WireTrame est un analyseur de protocoles réseau offline en mesure de comprendre les protocoles Ethernet,IP,UDP,DHCP,DNS.

Cet outil est codé en Python (3.9.9).

Les bibliothèques String, sys et Tkinter sont utilisées, veuillez également vérifier leur installation ainsi que leur bonne configuration.


Si vous avez des problèmes à ce sujet, nous vous invitons à consulter le lien suivant:
https://python.doctor/page-apprendre-installer-python-ordinateur


### LANCEMENT DU PROGRAMME "WireTrame.py":
Une fois l'installation vérifiée, vous pouvez lancer WireTrame:

Télecharger WireTrame.zip
	Ce dossier est composé en plus de ce fichier HOWTO, d'un code source, du code source éxécutable sans interface graphique, d'un makefile et enfin d'un README.

		SUR LINUX/MACOS:
		Ouvrez un terminal de commande (Konsole,Terminal par exemple)
		Vérifiez que vous êtes sur le bon répertoire (là où est situé WireTrame.zip)
		Lancez la commande "unzip WireTrame.zip"

		Vous devez désormais voir apparaître un nouveau dossier nommé "WireTrame"
		Placez votre terminal sur le bon répertoire
		Grace au makefile il vous suffit de lancer la commande "make"
			Au lancement de l'interface graphique vous aurez le choix entrer charger votre trace depuis un fichier ou depuis une saisie textuelle
			si l'entrée est bonne l'analyse s'effectue et vous aurez sur la partie haute le résumé des trames. en appuyant sur une trame l'analyse complète de la trame choisie est affichée dans la partie basse, en appuyant sur le triangle, un deuxième niveau apparaît à partir dequel il vous sera possible de selectionner la couche voulue ce qui fait passer l'affichage de la partie basse d'un résultat d'analyse complet à celui de la couche selectionné uniquement.

		5 choix différents se présent à vous à ce moment:
			-Tout effacer- : permettant d'effacer l'analyse de toutes les trames faisant que l'ajout d'une trace 			n'engendrera qu'elle même 
			-Charger fichier- : permettant de choisir un nouveau fichier à analyser
			-Charger texte- : permettant de lancer l'analyse d'une trace saisie au clavier
			-Sauvegarde selection- : permettant de sauvegarder dans un fichier la ou les trames selectionnnées
			-Tout Sauvegarder- : permettant de sauvegarder la totalité des trames analysées
			-Quitter- : sortie du programme


### LANCEMENT DU PROGRAMME "WireTrame_backup.py"
		SUR LINUX/MACOS:
		Ouvrez un terminal de commande (Konsole,Terminal par exemple)
		Vérifiez que vous êtes sur le bon répertoire (là où est situé WireTrame.zip)
		Lancez la commande "unzip WireTrame.zip"

		Le programme lancé vous demandera d'entrer le chemin vers la trace que vous souhaitez analyser:
		Un fichier nommé "Résultats.txt" est alors créé contenant toute l'analyse de la trace présente dans le fichier.

		

WireTrame prend en entrée des traces avec offset et conformes : 
Si la trame n'est pas conforme, un message d'erreur vous sera retourné sur le terminal, ainsi que sur l'écran selon la gravité de cette dernière, il faudra alors vérifier votre trace.



Copyright (C)
=============

  - 2021-2022 KORRABI Madjid, HALIT Yanis (WireTrame)
          under Python license (cf. `LICENSE.python`).

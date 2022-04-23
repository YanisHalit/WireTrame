#!/usr/bin/env python3
from tkinter import *
from tkinter import ttk
from tkinter.filedialog import *
from CodeSource import *
import re

global taille_ethernet, taille_ip, taille_udp, taille_dhcp, taille_dns, taille_tot
global ip_source, ip_destination, mac_source, mac_destination, P_ACTU
global T_ACTU, RES, L_TAILLE, TREE_FATHER, TREE_CHILDREND

input: str = ""

def new_trame(racine):
    global BOOL
    if BOOL == True:
        reset_list()
        BOOL = False
    interface(dem=racine)

def new_trame_input(racine, root):
    global BOOL
    root.destroy()
    racine.destroy()
    if BOOL == True:
        reset_list()
        BOOL = False
    interface("./ressources/NePasToucher.txt")

def save(don):
    s = ""
    if type(don) == dict:
        for i in don:
            s += don[
                     i] + "\n\n============================================================================================================\n\n"
    if type(don) == list:
        for i in don: s += i
    if type(don) == str : s = don
    with asksaveasfile(mode='wb', defaultextension='.txt', title='Save the file.') as f:
        f.write(s.encode('utf-8'))
        f.close()

def new_input(racine):
    root = Tk()
    root.title("Trame à analyser")
    root.geometry('500x400')
    root.configure(background='#E35A3B')

    def clear():
        my_text.delete(1.0, END)

    def save_file():
        text_file = open("./ressources/NePasToucher.txt", 'w')
        text_file.write(my_text.get(1.0,END))
        text_file.seek(0)
        new_trame_input(racine, root)


    def sortie():
        root.destroy()

    my_text = Text(root, width=60, height=20, fg = 'white',font=("Helvitica", 11), background='black')
    my_text.pack(pady=20)

    # button_frame = Frame(root)
    # button_frame.pack()



    save_button = Button(root,bd = 1, height = 1, text="Analyse", highlightbackground='green',command=save_file)
    save_button.pack(fill=X)

    clear_button = Button(root,bd = 1, height = 1, text="Effacer", command=clear)
    clear_button.pack(fill=X)

    close_button = Button(root,bd = 1, height = 1, text="Fermer", highlightbackground='red',command=root.destroy)
    close_button.pack(fill=X)


    my_label = Label(root, text='', background="#E35A3B")
    my_label.pack(pady=20)
    root.mainloop()

def demarrage():
    root = Tk()
    root.configure(background='#E35A3B')
    root.geometry("400x195")
    root.resizable(False, False)
    root.title("Bienvenue sur WireTrame")

    simple_label2 = Label(root, bd = 5,font=("Helvetica", 16), fg="black",text="De quelle façon souhaitez-vous charger votre/vos trace/s ?", background='#E35A3B')
    simple_label2.pack(side = TOP)
    fichier = Button(root,bd = 2, height = 3, text="Charger depuis un fichier",highlightbackground='blue', command=lambda: interface(dem=root))
    fichier.pack(fill = X)

    input = Button(root, bd = 2,height = 3, text="Charger depuis une saisie de texte", highlightbackground='green', command=lambda: new_input(root))
    input.pack(fill = X)

    quit = Button(root, bd = 2,height=2, text="Quitter", highlightbackground='red', command=lambda: exit())
    quit.pack()

    root.mainloop()

def interface(nom_fichier=None, dem=None):
    if dem != None:
        dem.destroy()
    # Base
    root = Tk()

    def new_text(racine):
        new_input(racine)

    root.title("Bienvenue sur WireTrame")
    root.configure(background='black')

    if not nom_fichier: nom_fichier = askopenfilename()

    if not nom_fichier :
        new_butto = Button(root, text="Nouveau Fichier", highlightbackground="blue", command=lambda: new_trame(root))
        simple_label2 = Label(root, highlightbackground='red' ,text="Erreur ouverture fichier.")
        input_butto = Button(root, text="Nouveau Texte", highlightbackground='green', command=lambda: new_input(root))

        closing_button2 = Button(root, text="Fermer", highlightbackground='red' ,command=quit)
        simple_label2.pack()
        new_butto.pack()
        input_butto.pack()
        closing_button2.pack()
        root.mainloop()

    try :
        program(nom_fichier)
    except :
        root.geometry("480x340")
        root.configure(background='white')

        simple_label2 = Label(root,background='white',fg = "black", text="Attention !\nLa trace choisie n'est pas analysable.\nVeuillez Jetter un coup d'oeil à votre terminal et réessayer.\n",font=("Helvetica", 17))
        simple_label2.pack()

        photo = PhotoImage(file='./ressources/attention.png')
        spath_label = Label(root, image=photo).pack()

        root.after(5000, lambda: root.destroy())
        root.mainloop()
        demarrage()

    root.geometry("900x600")
    my_frame = Frame(root, height = 100)
    labe1 = LabelFrame(root, bd = 1, background="black", text="Table", font=("Helvetica", 10))
    labe2 = LabelFrame(root,bd = 1, text="Trame", font=("Helvetica", 16), )
    lbl = Label(labe2, text="", background="black", anchor='nw', justify='left')

    style = ttk.Style()
    style.theme_use('clam')
    style.configure("Treeview",
                    background="black",
                    foreground="black",
                    rowheight=25,
                    fieldbackground="back"
                    )

    style.map("Treeview",
            background=[('selected', 'lightblue')])

    # creation treeview
    tree_frame = labe1

    # creation treeview scrollbar
    tree_scroll = Scrollbar(tree_frame)
    trame_scroll = Scrollbar(lbl, orient='vertical')
    # creation treeview
    my_tree = ttk.Treeview(tree_frame, yscrollcommand=tree_scroll.set)

    # configurer la scrollbar
    tree_scroll.configure(command=my_tree.yview)

    # Definir les colonnes
    my_tree['columns'] = ("Source", "Destination", "Protocol", "Length")

    # formater les colonnes
    my_tree.column("#0", anchor=W, width=440, minwidth=25)
    my_tree.column('Source', anchor=CENTER, width=130)
    my_tree.column('Destination', anchor=CENTER, width=130)
    my_tree.column('Protocol', anchor=CENTER, width=60)
    my_tree.column('Length', anchor=CENTER , width=60, minwidth=25)

    my_tree.heading("#0", text="N° Trame", anchor=CENTER)
    my_tree.heading("Source", text="Source", anchor=CENTER)
    my_tree.heading("Destination", text="Destination", anchor=CENTER)
    my_tree.heading("Protocol", text="Protocole", anchor=CENTER)
    my_tree.heading("Length", text="Longueur", anchor=CENTER)

    my_tree.tag_configure('oddrow', background="white")
    my_tree.tag_configure('evenrow', background="grey")

    for i in range (0,len(TREE_FATHER)):
        my_tree.insert(parent='', index="end",iid=i, text="Trame n°"+str(i+1), values= TREE_FATHER[i], tags=("evenrow") )
        elt = 0
        for cle, val in TREE_CHILDREN[i].items():
            if( val != "" ):
                tmp = cle.lower()
                my_tree.insert(parent=i, index="end",iid="elt"+str(i)+str(elt), text=(val), values=(f"",f"",f"",f'{L_TAILLE[i].get(tmp)}'), tags=("evenrow"))
                my_tree.move("elt"+str(i)+str(elt), i, elt)
                elt += 1

    # Boutons
    closing_button = Button(root, bd=1, text="Quitter", command=quit, highlightbackground='red')
    new_button = Button(root, bd=1, text="Charger fichier", command=lambda: new_trame(root), highlightbackground='blue')
    text_button = Button(root,  bd=1, text="Charger texte", command=lambda: new_text(root), highlightbackground='green')
    select_button = Button(root, bd=1, text="Sauvegarde selection", command=lambda: save_selection(), highlightbackground='#16A7A7')
    saveall_button = Button(root, bd=1, text="Tout Sauvegarder", command=lambda: save_all(), highlightbackground='grey')

    mycanva = Canvas(labe2)
    mycanva.pack(side=LEFT)

    yscrollbar = Scrollbar(mycanva, orient='vertical', command=mycanva.yview)
    yscrollbar.pack(side=RIGHT, fill='y')
    mycanva.configure(yscrollcommand=yscrollbar.set)
    mycanva.bind('<Configure>', lambda e: mycanva.configure(scrollregion=mycanva.bbox('all)')))

    myframe = Frame(mycanva, height = 400, width = 400)
    t = Text(myframe, yscrollcommand=yscrollbar.set, font=("Helvetica",14), width=100, height=1000)
    t.insert(1.0, "")
    t.pack()

    clear_button = Button(root, bd=2,text="Tout effacer", command=lambda: clear_all(t), highlightbackground='#000000')

    root.columnconfigure(1, weight=1)
    root.rowconfigure(1, weight=1)
    myframe.pack(fill=Y, expand='yes')
    labe1.grid(row=0, column=0,columnspan=10, sticky='n', padx = 5, pady=5)
    closing_button.grid(row=2, column=6, sticky = 's', padx = 5,pady=5)
    new_button.grid(row = 2, column = 3, sticky = 's', padx = 5,pady=5)
    text_button.grid(row=2,column=2, sticky = 's', padx =5 ,pady=5)
    select_button.grid(row=2,column=4, sticky = 's',padx = 5,pady=5)
    saveall_button .grid(row=2, column=5, sticky='s', padx=5, pady=5 )
    clear_button.grid(row=2, column=0, sticky='s', padx=5, pady=5 )

    labe2.grid(row = 1, column = 0,columnspan=10, sticky='n' )
    tree_scroll.grid(row = 1, column =10, rowspan=2)
    my_tree.grid(row = 1, column = 0,columnspan=10, sticky='n' )

    def selectItem(e=None):
        for i in my_tree.selection():
            s = ""
            if re.search("elt",i):
                tmp = str(i.replace("elt",""))
                n_prot = tmp[1]
                n_trame = tmp[0]
                n_trame = int(tmp[0])
                if n_prot == "0":
                    protocol = "ETHERNET"
                    t.delete(1.0, END)
                    s = RES[n_trame].get("ETHERNET")
                    t.insert(1.0, s)

                if n_prot == "1":
                    protocol = "IP"
                    t.delete(1.0, END)
                    s = RES[n_trame].get("IP")
                    t.insert(1.0, s)

                if n_prot == "2":
                    protocol = "UDP"
                    s = RES[n_trame].get("UDP")
                    t.delete(1.0, END)
                    t.insert(1.0, s)

                if n_prot == "3":
                    if RES[n_trame].get("DNS") == "":
                        protocol = "DHCP"
                        s = RES[n_trame].get("DHCP")
                        t.delete(1.0, END)
                        t.insert(1.0, s)

                    else:
                        protocol = "DNS"
                        s = RES[n_trame].get("DNS")
                        t.delete(1.0, END)
                        t.insert(1.0, s)
            else:
                s = ""
                tmp = i
                n_trame = tmp[0]
                n_trame = int(tmp[0])
                for cle, val in RES[n_trame].items():
                    s+=val
                t.delete(1.0, END)
                t.insert(1.0, s)

    def save_selection(e=None) :
        s = ""
        for i in my_tree.selection():
            if re.search("elt",i):
                continue
            else :
                tmp = i
                n_trame = tmp[0]
                n_trame = int(tmp[0])
                for cle, val in RES[n_trame].items():
                    s+=val
            s += "\n\n============================================\n"
        save(s)

    def save_all():
        s = ""
        for i in range(0, len(RES)):
            for cle, val in RES[i].items():
                if val != "" and cle != None: s += val
            s += "\n\n====================\n\n"

        save(s)

    def clear_all(t):
        global BOOL
        t.delete("1.0","end")
        for i in my_tree.get_children():
            my_tree.delete(i)
        BOOL = True

    my_tree.bind("<ButtonRelease-1>", selectItem)

    root.mainloop()

demarrage()

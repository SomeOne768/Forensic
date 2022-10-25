# TP Forensic : Intruder 

# Abdeljalil ZOGHLAMI


## 1 . Acquisition des données

Verification du hash:
```
cmd: sha256sum forensic_trainings_storage_001.dd 
result: be7de1857c72a7abe8b00198b01ca11cd9ffffda081ad278fe8a9f6f0f54ead0  forensic_trainings_storage_001.dd
````

Le hash correspond à celui sur lequel on doit enquêter.

## 2.Investigation

On commence par regarder le **Master Boot Record**
```
mmls forensic_trainings_storage_001.dd
```
Nous avons 4 partitions.
On remarque 2 parties non allouées et en particulier une se trouvant entre 2 partitions.

A l'aide du programme python (annexe) ou de la commande ci-dessous, on détermine les types de partition et on récupère les différentes informations.
```
file forensic_trainings_storage_001.dd
```
On y remarque que les secteurs ne se suivent pas.
Voici un tableau des informations obtenue:

| | START | END |
| :-: | :-: | :-: |

| | C | H | S | C | H | S |
|:-: | :-: | :-: | :-: | :-: | :-: | :-: |
| P1 | 0  | 32 | 33 | 7F | 187 | 60|
| P2 | 7F | 187 | 61| BF | 121 | 58|
| P3 | BF | 121 | 59 | 152 | 5 | 3 |
| P4 | 183 | 74 | 8 | 1e4| 254 | 59 |

Espace mmoire contigüe: P3 ES => P4 SS
Il y a donc un trou entre les secteurs de la partion 3 et 4.

Autre explication : les partitions sont rangées à la fin. Il est donc "normal" d’avoir des trous au début en revanche des trous entre plusieurs partitions non et surtout pas à la fin.

A l'aide de mmls on récupère les offset qui nous permettront d'accéder au différentes partitons

| Partition | Offset |
|:-: | :-: |
| P1 | 2048 |
| P2 | 2052096 | 
| P3 | 3076096 | 
|Non alloué | 5173248 |
| P4 | 6221824 |

Avec fsstat on voit que cette partie non allouée est possiblement chiffrée. Cependant cela peut-être dû au fait qu’elle ne respecte pas le format attendu et donc la commande pense que c’est chiffré.
```
fsstat forensic_trainings_storage_001.dd -o 5173248
```
On peut lire:
```
Possible encryption detected (High entropy (7,99))
```


### 2.1. Première partition
Ici, on commence par s'intéresser à la première partition.

System de fichier: NTFS 
OS : Windows XP 

Commençons par regarder les inodes des fichiers supprimés:

```
ils forensic_trainings_storage_001.dd -o 2048
```
On s’aperçoit que le numéro des inodes fait un “saut”. On passe de 23 à **66** et de la même manière, les droits des fichiers suivants sont passés en 777. De plus on s’aperçoit que le fichier **inode 66** est le premier fichier de taille > 0. Idem ensuite pour le saut en 73.
Dans la suite on évoquera les fichiers : **file003-renamed**[.swp ou pas]  
ainsi que du dossier: **folder001** d'inode 64

On se rend compte que c’est l’utilisateur 48 (uid) qui est propriétaire des fichiers suspect de la partition 1. De plus, on trouve des inodes supplémentaire 64 et 65 qui apparaissent avec l’option -me. Il est donc interessant de voir que le dossier, qui contient les fichiers précédemment cités et qui ont été supprimé, toujours présent. 

On y voit le format swp. Cette extension se crée lorsque vi est utilisé. 
On peut penser que c’est quelqu’un qui a donc executé des commandes car les vrais codeurs n’utilisent pas vi(m) :).

*Question : Est-il possible que le fichier003 renommé soit un copie du fichier001 que l'on a modifi par la suite*

Récupérons l'horodatage du dossier où l'on a écrit avec vi:
```
istat  forensic_trainings_storage_001.dd  -o 2048 64
MFT Entry Header Values:
Entry: 64        Sequence: 1
$LogFile Sequence Number: 0
Allocated Directory
Links: 1

$STANDARD_INFORMATION Attribute Values:
Flags: Archive
Owner ID: 0
Security ID: 0  ()
Created:	2022-10-06 14:24:21.299243500 (CEST)
File Modified:	2022-10-06 14:28:52.486202900 (CEST)
MFT Modified:	2022-10-06 14:28:52.486202900 (CEST)
Accessed:	2022-10-06 14:29:09.543827600 (CEST)

$FILE_NAME Attribute Values:
Flags: Directory, Archive
Name: folder001
Parent MFT Entry: 5 	Sequence: 5
Allocated Size: 0   	Actual Size: 0
Created:	2022-10-06 14:24:21.299243500 (CEST)
File Modified:	2022-10-06 14:24:21.299243500 (CEST)
MFT Modified:	2022-10-06 14:24:21.299243500 (CEST)
Accessed:	2022-10-06 14:24:21.299243500 (CEST)

Attributes: 
Type: $STANDARD_INFORMATION (16-0)   Name: N/A   Resident   size: 48
Type: $FILE_NAME (48-3)   Name: N/A   Resident   size: 84
Type: $SECURITY_DESCRIPTOR (80-1)   Name: N/A   Resident   size: 80
Type: $INDEX_ROOT (144-2)   Name: $I30   Resident   size: 56
Type: $INDEX_ALLOCATION (160-5)   Name: $I30   Non-Resident   size: 4096  init_size: 4096
32144 
Type: $BITMAP (176-4)   Name: $I30   Resident   size: 8
```

On y trouve l'offset 32144 qui nous permet de nous déplacer dans la partition à l'endroit du dossier.

```
blkcat forensic_trainings_storage_001.dd -o 2048 32144 -h
0	494e4458 28000900 00000000 00000000 	INDX (... .... .... 
16	00000000 00000000 28000000 18010000 	.... .... (... .... 
32	e80f0000 00000000 27003300 00000000 	.... .... '.3. .... 
48	00000000 00000000 00000000 00000000 	.... .... .... .... 
64	41000000 00000100 70005e00 00000000 	A... .... p.^. .... 
80	40000000 00000100 c5bdf49c 7ed9d801 	@... .... .... ~... 
96	e7e5f6b4 7ed9d801 e7e5f6b4 7ed9d801 	.... ~... .... ~... 
112	2750f7b4 7ed9d801 18000000 00000000 	'P.. ~... .... .... 
128	17000000 00000000 20000000 00000000 	.... ....  ... .... 
144	0e006600 69006c00 65003000 30003100 	..f. i.l. e.0. 0.1. 
160	2d006300 72006500 61007400 65000000 	-.c. r.e. a.t. e... 
176	48000000 00000200 70006000 00000000 	H... .... p.`. .... 
192	40000000 00000100 2088a931 7fd9d801 	@... ....  ..1 .... 
208	f08da931 7fd9d801 f08da931 7fd9d801 	...1 .... ...1 .... 
224	f9eca931 7fd9d801 40000000 00000000 	...1 .... @... .... 
240	3d000000 00000000 20000000 00000000 	=... ....  ... .... 
256	0f006600 69006c00 65003000 30003300 	..f. i.l. e.0. 0.3. 
272	2d007200 65006e00 61006d00 65006400 	-.r. e.n. a.m. e.d. 
288	00000000 00000000 10000000 02000000 	.... .... .... .... 
304	48000000 00000200 70006000 00000000 	H... .... p.`. .... 
320	40000000 00000100 2088a931 7fd9d801 	@... ....  ..1 .... 
336	f08da931 7fd9d801 f08da931 7fd9d801 	...1 .... ...1 .... 
352	f9eca931 7fd9d801 40000000 00000000 	...1 .... @... .... 
368	3d000000 00000000 20000000 00000000 	=... ....  ... .... 
384	0f006600 69006c00 65003000 30003300 	..f. i.l. e.0. 0.3. 
400	2d007200 65006e00 61006d00 65006400 	-.r. e.n. a.m. e.d. 
416	00000000 00000000 10000000 02000000 	.... .... .... .... 
432	40000000 00000100 7bbc1731 7fd9d801 	@... .... {..1 .... 
448	5fc51731 7fd9d801 1584a931 7fd9d801 	_..1 .... ...1 .... 
464	8f381831 7fd9d801 40000000 00000000 	.8.1 .... @... .... 
480	3d000000 00000000 20000000 00000000 	=... ....  ... .... 
496	10006600 69006c00 65003000 30002700 	..f. i.l. e.0. 0.'. 
512	2d007200 65006e00 61006d00 65006400 	-.r. e.n. a.m. e.d. 
```

Les fichiers précédents sont bien visible cependant un autre fichier semble apparaitre [ file00'-renamed]

Enfin, on liste tous les fichiers supprimé dans cette partition (hormis une catégorie que l'on suppose être crée par le systeme lors de la manipulation).
```
fls -r forensic_trainings_storage_001.dd -o 2048 -lp -m "/" | grep "(deleted)" | grep -v "OrphanFile"
```

On s’interesse donc à ce fichier supprimer on voit que :  

```
icat forensic_trainings_storage_001.dd -o 2048 66-128-2 | xxd | grep -v "0000 0000 0000 0000 0000 0000 0000 0000"
[Pour cette commande probleme en mettant le grep -v "................"]
00000000: 6230 5649 4d20 382e 3200 0000 0010 0000  b0VIM 8.2.......
00000010: 70c9 3e63 4800 0000 4c2e 0000 6368 7269  p.>cH...L...chri
00000020: 7300 0000 0000 0000 0000 0000 0000 0000  s...............
00000040: 0000 0000 6465 6269 616e 0000 0000 0000  ....debian......
00000060: 0000 0000 0000 0000 0000 0000 2f6d 6564  ............/med
00000070: 6961 2f63 6872 6973 2f31 4441 4246 3133  ia/chris/1DABF13
00000080: 4230 3230 3330 3430 382f 666f 6c64 6572  B02030408/folder
00000090: 3030 312f 6669 6c65 3030 332d 7265 6e61  001/file003-rena
000000a0: 6d65 6400 0000 0000 0000 0000 0000 0000  med.............
000003e0: 0000 0000 0000 0000 0075 7466 2d38 0d00  .........utf-8..
000003f0: 3332 3130 0000 0000 2322 2120 1312 5500  3210....#"! ..U.
00001000: 7470 0100 7f00 0000 0200 0000 0000 0000  tp..............
00001010: 0100 0000 0000 0000 0100 0000 0000 0000  ................
00001020: 0100 0000 0000 0000 0000 0000 0000 0000  ................
00002000: 6164 0000 a30f 0000 c30f 0000 0010 0000  ad..............
00002010: 0100 0000 0000 0000 c30f 0000 e80f 0000  ................
00002fc0: 0000 0053 4756 3549 5342 5561 476c 7a49  ...SGV5ISBUaGlzI
00002fd0: 476c 7a49 4746 7549 4756 3459 5731 7762  GlzIGFuIGV4YW1wb
00002fe0: 4755 6762 3259 6759 6d46 7a5a 5459 3049  GUgb2YgYmFzZTY0I
00002ff0: 4756 7559 3239 6b61 5735 6e4c 673d 3d00  GVuY29kaW5nLg==.
```

On y trouve quelque chose d'interessant:
**Chris debian**
Sur linux /media est le point de montage par défaut. Tous les médias, CD-ROM, HDD USB, clés USB, sont montés automatiquement dans ce dossier. 
On y retrouve l'amour des CTF de notre prof, notamment un petit code en base 64: 

```
code: SGV5ISBUaGlzIGlzIGFuIGV4YW1wbGUgb2YgYmFzZTY0IGVuY29kaW5nLg== 
decodé en utf8: Hey! This is an example of base64 encoding.
```

Les autres fichiers de cette partitions qui semblaient intéressant n'ont rien donné de plus (seul le fichier d'inode 73 nous redonnera ce même code base64).






















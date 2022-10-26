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

Verification du hash:
```
cmd: sha256sum forensic_trainings_storage_001.dd 
result: be7de1857c72a7abe8b00198b01ca11cd9ffffda081ad278fe8a9f6f0f54ead0  forensic_trainings_storage_001.dd
````

Le hash correspond toujours, on a donc rien corrompue jusqu'ici.

### 2.2. Deuxième partition

Maintenant qu'on connait un peu le fonctionnement, on va pouvoir chercher plus efficacement.

Récupération des informations primaire
```
mmls forensic_trainings_storage_001.dd
```

Systeme de fichier: NTFS


```
file forensic_trainings_storage_001.dd
```

Récupération des fichiers supprimés:
```
ils forensic_trainings_storage_001.dd -o 2048
```
inode 16 à 23.
```
istat  forensic_trainings_storage_001.dd  -o 2048 64
```
Ces fichiers ont tous été crée au même moment et la même journée que nos fichier suspect de la partition prcédente.

Esseyons de lire ce qu'il y a à l'intérieur:
```
blkcat forensic_trainings_storage_001.dd -o 2052096 20 -h | grep -v "00000000 00000000 00000000 00000000" 
0	46494c45 30000300 00000000 00000000 	FILE 0... .... .... 
16	01000100 38000300 90020000 00040000 	.... 8... .... .... 
32	00000000 00000000 04000000 40000000 	.... .... .... @... 
48	0a006500 00000000 10000000 48000000 	..e. .... .... H... 
64	00000000 00000000 30000000 18000000 	.... .... 0... .... 
80	39819566 7fd9d801 3b86496e 7fd9d801 	9..f .... ;.In .... 
96	3b86496e 7fd9d801 9c699d77 7fd9d801 	;.In .... .i.w .... 
112	20000000 00000000 00000000 00000000 	 ... .... .... .... 
128	30000000 70000000 00000000 00000300 	0... p... .... .... 
144	52000000 18000100 05000000 00000500 	R... .... .... .... 
160	39819566 7fd9d801 39819566 7fd9d801 	9..f .... 9..f .... 
176	39819566 7fd9d801 39819566 7fd9d801 	9..f .... 9..f .... 
208	20000010 00000000 08007400 72006100 	 ... .... ..t. r.a. 
224	6e007300 66006500 72000000 50000000 	n.s. f.e. r... P... 
240	50000000 68000000 00000000 00000100 	P... h... .... .... 
256	50000000 18000000 01000480 14000000 	P... .... .... .... 
272	24000000 00000000 34000000 01020000 	$... .... 4... .... 
288	00000005 20000000 20020000 01020000 	....  ...  ... .... 
304	00000005 20000000 20020000 02001c00 	....  ...  ... .... 
320	01000000 00031400 ff011f00 01010000 	.... .... .... .... 
336	00000001 00000000 90000000 30010000 	.... .... .... 0... 
352	00041800 00000200 10010000 20000000 	.... .... ....  ... 
368	24004900 33003000 30000000 01000000 	$.I. 3.0. 0... .... 
384	00100000 01000000 10000000 00010000 	.... .... .... .... 
400	00010000 00000000 41000000 00000100 	.... .... A... .... 
416	70005e00 00000000 40000000 00000100 	p.^. .... @... .... 
432	0367496e 7fd9d801 ec6f496e 7fd9d801 	.gIn .... .oIn .... 
448	ec6f496e 7fd9d801 0d9fa567 80d9d801 	.oIn .... ...g .... 
464	18000000 00000000 17000000 00000000 	.... .... .... .... 
480	20000000 00000000 0e006600 69006c00 	 ... .... ..f. i.l. 
496	65003000 30003100 2d006300 72000a00 	e.0. 0.1. -.c. r... 
512	61007400 65000000 42000000 00000100 	a.t. e... B... .... 
528	70006000 00000000 40000000 00000100 	p.`. .... @... .... 
544	de85496e 7fd9d801 bc8b496e 7fd9d801 	..In .... ..In .... 
560	bc8b496e 7fd9d801 c4d2a567 80d9d801 	..In .... ...g .... 
576	40000000 00000000 3d000000 00000000 	@... .... =... .... 
592	20000000 00000000 0f006600 69006c00 	 ... .... ..f. i.l. 
608	65003000 30003300 2d007200 65006e00 	e.0. 0.3. -.r. e.n. 
624	61006d00 65006400 00000000 00000000 	a.m. e.d. .... .... 
640	10000000 02000000 ffffffff 00000000 	.... .... .... .... 
1008	00000000 00000000 00000000 00000a00 	.... .... .... .... 
1024	46494c45 30000300 00000000 00000000 	FILE 0... .... .... 
1040	01000100 38000100 98010000 00040000 	.... 8... .... .... 
1056	00000000 00000000 04000000 41000000 	.... .... .... A... 
1072	06000000 00000000 10000000 48000000 	.... .... .... H... 
1088	00000000 00000000 30000000 18000000 	.... .... 0... .... 
1104	0367496e 7fd9d801 ec6f496e 7fd9d801 	.gIn .... .oIn .... 
1120	ec6f496e 7fd9d801 0d9fa567 80d9d801 	.oIn .... ...g .... 
1136	20000000 00000000 00000000 00000000 	 ... .... .... .... 
1152	30000000 78000000 00000000 00000300 	0... x... .... .... 
1168	5e000000 18000100 40000000 00000100 	^... .... @... .... 
1184	0367496e 7fd9d801 0367496e 7fd9d801 	.gIn .... .gIn .... 
1200	0367496e 7fd9d801 0367496e 7fd9d801 	.gIn .... .gIn .... 
1216	18000000 00000000 00000000 00000000 	.... .... .... .... 
1232	20000000 00000000 0e006600 69006c00 	 ... .... ..f. i.l. 
1248	65003000 30003100 2d006300 72006500 	e.0. 0.1. -.c. r.e. 
1264	61007400 65000200 50000000 68000000 	a.t. e... P... h... 
1280	00000000 00000100 50000000 18000000 	.... .... P... .... 
1296	01000480 14000000 24000000 00000000 	.... .... $... .... 
1312	34000000 01020000 00000005 20000000 	4... .... ....  ... 
1328	20020000 01020000 00000005 20000000 	 ... .... ....  ... 
1344	20020000 02001c00 01000000 00031400 	 ... .... .... .... 
1360	ff011f00 01010000 00000001 00000000 	.... .... .... .... 
1376	80000000 30000000 00000000 00000200 	.... 0... .... .... 
1392	17000000 18000000 74686973 20697320 	.... .... this  is  
1408	61707065 6e64696e 67206461 74610a00 	appe ndin g da ta.. 
1424	ffffffff 00000000 00000000 00000000 	.... .... .... .... 
1520	00000000 00000000 00000000 00000600 	.... .... .... .... 
2032	00000000 00000000 00000000 00000600 	.... .... .... .... 
2048	46494c45 30000300 00000000 00000000 	FILE 0... .... .... 
2064	01000100 38000100 c0010000 00040000 	.... 8... .... .... 
2080	00000000 00000000 04000000 42000000 	.... .... .... B... 
2096	06000000 00000000 10000000 48000000 	.... .... .... H... 
2112	00000000 00000000 30000000 18000000 	.... .... 0... .... 
2128	de85496e 7fd9d801 bc8b496e 7fd9d801 	..In .... ..In .... 
2144	bc8b496e 7fd9d801 c4d2a567 80d9d801 	..In .... ...g .... 
2160	20000000 00000000 00000000 00000000 	 ... .... .... .... 
2176	30000000 78000000 00000000 00000300 	0... x... .... .... 
2192	60000000 18000100 40000000 00000100 	`... .... @... .... 
2208	de85496e 7fd9d801 de85496e 7fd9d801 	..In .... ..In .... 
2224	de85496e 7fd9d801 de85496e 7fd9d801 	..In .... ..In .... 
2240	40000000 00000000 00000000 00000000 	@... .... .... .... 
2256	20000000 00000000 0f006600 69006c00 	 ... .... ..f. i.l. 
2272	65003000 30003300 2d007200 65006e00 	e.0. 0.3. -.r. e.n. 
2288	61006d00 65006400 50000000 68000000 	a.m. e.d. P... h... 
2304	00000000 00000100 50000000 18000000 	.... .... P... .... 
2320	01000480 14000000 24000000 00000000 	.... .... $... .... 
2336	34000000 01020000 00000005 20000000 	4... .... ....  ... 
2352	20020000 01020000 00000005 20000000 	 ... .... ....  ... 
2368	20020000 02001c00 01000000 00031400 	 ... .... .... .... 
2384	ff011f00 01010000 00000001 00000000 	.... .... .... .... 
2400	80000000 58000000 00000000 00000200 	.... X... .... .... 
2416	3d000000 18000000 53475635 49534255 	=... .... SGV5 ISBU 
2432	61476c7a 49476c7a 49474675 49475634 	aGlz IGlz IGFu IGV4 
2448	59573177 62475567 62325967 596d467a 	YW1w bGUg b2Yg YmFz 
2464	5a545930 49475675 5932396b 6157356e 	ZTY0 IGVu Y29k aW5n 
2480	4c673d3d 0a000000 ffffffff 00000000 	Lg== .... .... ....
```
Seul le fichier d'inode 20 n'est pas vide.
On retrouve le même code que précédemennt et on peut lire une fois de plus "file003-renamed".

Chercher parmis les fichiers non supprimés
```
ils forensic_trainings_storage_001.dd -o 2052096  -me
0|<forensic_trainings_storage_001.dd-transfer-alive-64>|64|-/drwxrwxrwx|48|0|272|1665059449|1665059434|1665059434|1665059421
0|<forensic_trainings_storage_001.dd-file001-create-alive-65>|65|-/rrwxrwxrwx|48|0|23|1665059852|1665059434|1665059434|1665059434
0|<forensic_trainings_storage_001.dd-file003-renamed-alive-66>|66|-/rrwxrwxrwx|48|0|61|1665059852|1665059434|1665059434|1665059434
```
Le même uid revient avec les droits maximaux sur ces fichers. Cependant ces derniers sont vides.
Cependant on ne trouveras rien  de bien intéressant.


### 2.3. Troisième partition



Systeme de fichier fat16

```
ils forensic_trainings_storage_001.dd -o 3076096
class|host|device|start_time
ils|jalil-580-054nf||1666809163
st_ino|st_alloc|st_uid|st_gid|st_mtime|st_atime|st_ctime|st_crtime|st_mode|st_nlink|st_size
```
Pas de fichier supprimé.

```
jalil@jalil-580-054nf:~/Documents/ZZ2/forensic$ ils forensic_trainings_storage_001.dd -o 3076096 -me
md5|file|st_ino|st_ls|st_uid|st_gid|st_size|st_atime|st_mtime|st_ctime|st_crtime
0|<forensic_trainings_storage_001.dd--alive-2>|2|-/d---------|0|0|16384|0|0|0|0
0|<forensic_trainings_storage_001.dd-$MBR-alive-33545603>|33545603|-/v---------|0|0|512|0|0|0|0
0|<forensic_trainings_storage_001.dd-$FAT1-alive-33545604>|33545604|-/v---------|0|0|131072|0|0|0|0
0|<forensic_trainings_storage_001.dd-$FAT2-alive-33545605>|33545605|-/v---------|0|0|131072|0|0|0|0
0|<forensic_trainings_storage_001.dd-$OrphanFiles-alive-33545606>|33545606|-/V---------|0|0|0|0|0|0|0
```
Rien qui ne semble suspect


```
jalil@jalil-580-054nf:~/Documents/ZZ2/forensic$ fls forensic_trainings_storage_001.dd -o 3076096 -me
0|e/$MBR|33545603|v/v---------|0|0|512|0|0|0|0
0|e/$FAT1|33545604|v/v---------|0|0|131072|0|0|0|0
0|e/$FAT2|33545605|v/v---------|0|0|131072|0|0|0|0
0|e/$OrphanFiles|33545606|V/V---------|0|0|0|0|0|0|0
jalil@jalil-580-054nf:~/Documents/ZZ2/forensic$ istat forensic_trainings_storage_001.dd -o 3076096 0
Metadata address is too small for image (2)
```
```
fsstat forensic_trainings_storage_001.dd -o 3076096
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: FAT16

METADATA INFORMATION
--------------------------------------------
Range: 2 - 33545606

```
Il semble difficile d'accéder à cette partition. De plus, on peut lire "MBR FAT1 et FAT2". Cette partition contient en fait elle même d'autres partitions. En se souvenant qu'une partie non alloué la succèdent et qu'en plus on y trouve très peut de "fichier" alors que la range va de 2 à 33545606.
L'investigation devrait donc surement être appronfondie de ce côté.

### 2.4. Quatrième partition

```
fsstat forensic_trainings_storage_001.dd -o 6221824
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name: 
Volume ID: 972eefe143fdeb95584232f896ce8533

Last Written at: 2022-10-06 14:38:11 (CEST)
Last Checked at: 2022-10-06 14:14:57 (CEST)

Last Mounted at: 2022-10-06 14:32:21 (CEST)
Unmounted properly
Last mounted on: /media/chris/3385ce96-f832-4258-95eb-fd43e1ef2e97
Source OS: Linux
```

Systeme de fichier Ext4
OS: Linux

Point intéressant: monté sur notre clé USB et dernière écriture après le fichier suspect de la partition 1


On découvre un fichier zip
```
fls forensic_trainings_storage_001.dd -o 6221824
d/d 11:	lost+found
r/r * 12(realloc):	ziiBIfHf
r/r 12:	archive.zip
d/d 7089:	extrafolder_from_unzip
V/V 49617:	$OrphanFiles


icat forensic_trainings_storage_001.dd -o 6221824 12 | xxd
00000000: 504b 0304 0a00 0000 0000 9a73 4655 0000  PK.........sFU..
00000010: 0000 0000 0000 0000 0000 0a00 1c00 666f  ..............fo
00000020: 6c64 6572 3030 312f 5554 0900 0304 ca3e  lder001/UT.....>
00000030: 6315 ca3e 6375 780b 0001 04e8 0300 0004  c..>cux.........
00000040: e803 0000 504b 0304 0a00 0000 0000 2c73  ....PK........,s
00000050: 4655 75ae fab2 1700 0000 1700 0000 1800  FUu.............
00000060: 1c00 666f 6c64 6572 3030 312f 6669 6c65  ..folder001/file
00000070: 3030 312d 6372 6561 7465 5554 0900 0333  001-createUT...3
00000080: c93e 6333 c93e 6375 780b 0001 04e8 0300  .>c3.>cux.......
00000090: 0004 e803 0000 7468 6973 2069 7320 6170  ......this is ap
000000a0: 7065 6e64 696e 6720 6461 7461 0a50 4b03  pending data.PK.
000000b0: 0414 0000 0008 009a 7346 5525 4091 bb3a  ........sFU%@..:
000000c0: 0000 003d 0000 0019 001c 0066 6f6c 6465  ...=.......folde
000000d0: 7230 3031 2f66 696c 6530 3033 2d72 656e  r001/file003-ren
000000e0: 616d 6564 5554 0900 0304 ca3e 6304 ca3e  amedUT.....>c..>
000000f0: 6375 780b 0001 04e8 0300 0004 e803 0000  cux.............
00000100: 0b76 0f33 f50c 760a 4d74 cfa9 f204 63b7  .v.3..v.Mt....c.
00000110: 524f f730 93c8 70c3 f224 f7d0 f424 a3c8  RO.0..p..$...$..
00000120: f4c8 5cb7 aaa8 9048 03a0 7869 a491 6576  ..\....H..xi..ev
00000130: 62b8 699e 4fba ad2d 1700 504b 0102 1e03  b.i.O..-..PK....
00000140: 0a00 0000 0000 9a73 4655 0000 0000 0000  .......sFU......
00000150: 0000 0000 0000 0a00 1800 0000 0000 0000  ................
00000160: 1000 ff41 0000 0000 666f 6c64 6572 3030  ...A....folder00
00000170: 312f 5554 0500 0304 ca3e 6375 780b 0001  1/UT.....>cux...
00000180: 04e8 0300 0004 e803 0000 504b 0102 1e03  ..........PK....
00000190: 0a00 0000 0000 2c73 4655 75ae fab2 1700  ......,sFUu.....
000001a0: 0000 1700 0000 1800 1800 0000 0000 0100  ................
000001b0: 0000 ff81 4400 0000 666f 6c64 6572 3030  ....D...folder00
000001c0: 312f 6669 6c65 3030 312d 6372 6561 7465  1/file001-create
000001d0: 5554 0500 0333 c93e 6375 780b 0001 04e8  UT...3.>cux.....
000001e0: 0300 0004 e803 0000 504b 0102 1e03 1400  ........PK......
000001f0: 0000 0800 9a73 4655 2540 91bb 3a00 0000  .....sFU%@..:...
00000200: 3d00 0000 1900 1800 0000 0000 0100 0000  =...............
00000210: ff81 ad00 0000 666f 6c64 6572 3030 312f  ......folder001/
00000220: 6669 6c65 3030 332d 7265 6e61 6d65 6455  file003-renamedU
00000230: 5405 0003 04ca 3e63 7578 0b00 0104 e803  T.....>cux......
00000240: 0000 04e8 0300 0050 4b05 0600 0000 0003  .......PK.......
00000250: 0003 000d 0100 003a 0100 0000 00         .......:.....
```

Encore une fois on retombe à ce fameux file003 du dosser folder001 qui a été renommé.
On reviendra plus tard faire une copie de ce dernier pour l'exploiter






















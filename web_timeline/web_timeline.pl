#!/usr/bin/perl
# web_timeline.pl 1.0
# 28/02/2008
# Juan Manuel Ramon (jmanuel@bacchuss.com.ar)

require 'getopts.pl';
# permite especificar los archivos/directorios de trabajo (patrones y logs)

#use Algorithm::AhoCorasick qw(find_first);
#rutina de deteccion de patrones O(n)
#Debe ser instalada previamente

#----------------------------------------------------------------------------------------------------
#1 Menu de la aplicacion, variables de input y mensajes
Getopts('h:r:t:d:x:z');

if ($opt_h) {
die "\
Uso: $0 [-t <archivo_de_log> || -d <riectorio_de_logs> ] \
\t-x debug\tPermite setear marcadores de control.\
\t-h help\t\tDonde estas?.\
\t **Importante!: en el directorio [./timeline_logs] se almacenan los resulatdos del analisis.\
\n";
}

if ($opt_z)
{&delete_logs();}

if (!$opt_t && !$opt_d) {die "Falta especificar el archivo/directorio de logs a analizar(-t/-d), o \n(-z) para borrar logs de ejecuciones anteriores  para borrar logs anteriores.\n";}

my $data_file = $opt_t;
my $data_dir = $opt_d;
my $val = $opt_z;


$direc = "./logs_timeline";


if (-d $direc) 
{
#print "AAAA Directorio $direc existe \n";
$dy = `rm -f $direc/*.log`;
}
else 
{
#print "AAAA Directorio $direc NO existe, creado \n";
$diresult = `mkdir $direc`;
}

$usuario = `whoami`;
$dir = `pwd`;
($fecha,$hora) = &time_stamp();

sub time_stamp {
my ($d,$t);
my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
$year += 1900;
$mon++;
$d = sprintf("%4d-%2.2d-%2.2d",$year,$mon,$mday);
$t = sprintf("%2.2d:%2.2d:%2.2d",$hour,$min,$sec);
return($d,$t);
}

print "\n";
print "--------------------------------------------------------------------------------------------------------\n";
print "WEB_TIMELINE es una aplicacion para analisis forense de actividades web sobre Plat MS IIS.\n";
print "**Importante!: en el directorio [./timeline_logs] se almacenan los resulatdos del analisis.>\n";
print "Cualquier comentario a <jmanuel\@bacchuss.com.ar>\n";
print "\n";
print "---------------------------------------------------------------------------------------------------------\n";

if ($data_file) {
print "Procesando archivo de logs: ........................... $data_file.\n";
}

if ($data_dir) {
print "Procesando directorio de logs: ........................ $data_dir\n";
}



#----------------------------------------------------------------------------------------------------
#3 Bloque de carga de patrones de detecci�n (-r)

print "\n";
print "               ***  COMIENZO ANALISIS   ***                                    \n";
print "\n";


#----------------------------------------------------------------------------------------------------
#4 Bloque de Procesamiento de archivo de logs (-t)
if ($data_file) 
{

open(FILE, "$data_file") or die("Imposible abrir archivo de log $data_file.\n");
@data = <FILE>;
$index = 0;
$ind =0;
close (FILE);

&detecta (@data);

print "--------------------------------------------------------------------------------------------------------\n";
print "Se han procesado $index lineas de datos del archivo de log: $data_file.\n";
print "\n";

# Fin bloque de proceso de archivo de logs
}


#################################################################################################

if ($data_dir) 
{
opendir(IMD, $data_dir) || die("No es posible acceder al directorio de logs.\n");
@logs= readdir(IMD);
closedir(IMD);

$cf=0;

foreach $f (@logs)
{
$cf = $cf +1;
if ($f eq '.') { next;}
if ($f eq '..') { next;}

$abs_path=$data_dir.$f;

open(FILE, "$abs_path") or die("Imposible abrir archivo de log $data_file.\n");
@data = <FILE>;
close(FILE);
$index = 0;
$ind =0;

&detecta (@data);

print "--------------------------------------------------------------------------------------------------------\n";
print "Se han procesado $index lineas de datos del archivo de log: $f.\n";
print "\n";

# Fin bloque de proceso de archivo de logs

}
}
		


###########################################################
############################################################3

sub detecta 
{

foreach $linexx (@data)
{
chomp ($linexx);
$index = $index + 1;

if ($linexx =~ /^\s*#/ || $linexx eq "\n" ) { next;}

############################################################
# Normalizacion de patron (ASCII -> Char), (Cap.Let -> Low.Let)
#$linexx =~ tr/+/ /;
$linexx =~ s/%([a-fA-F0-9]{2,2})/chr(hex($1))/eg;
$linexx =~ s/<!--(.|\n)*-->//g;
$linexx =~ tr/A-Z/a-z/;


#############################################################
# Parseo las lineas para extraer parametros

#2007-08-01 00:50:48 139.18.2.68 - 192.168.204.23 80 GET /pia/Binaria_Seguros/seguro_retiro_colectivo.asp - 200 0 findlinks/1.1.4-beta1+(+http://wortschatz.uni-leipzig.de/findlinks/) - -
$linexx =~ /(\S+)\s+(\S+)\s+(\S+)\s+\S\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)\s+(\d\d\d)\s+(\d+)\s+(.+)\s+(.+)\s+(.+)/;

$fecha = $1;
$hora = $2;
$sip = $3;
$dip = $4;
$port = $5;
$metodo = $6;
$payload = $7;
$resultado = $8;
$octetos = $9;
$agente = $10;
$cookie = $11;
$referrer = $12;

##########################################################################
#Bloque de deteccion de ataques - INICIO

#Extraccion de datos 1
if ( $linexx =~ /select/ && $linexx =~ /case/ && $linexx =~ /syntax_error/ && $linexx =~ /500/)
{
$payload =~ /syntax_error_converting_the_nvarchar_value_'(.*[^+]\S+)'_to_a_column_of_data_type/;
$dato=$1;
$accion="Extraccion de Informacion";
#@datos[$ind] = $dato;
$ind = $ind +1;
&historial ($accion, $sip, $fecha, $hora, $dato);
}

#Extraccion de datos 2
elsif ( $linexx =~ /select/ && $linexx =~ /500/ && $linexx =~ /syntax_error/)
{
$payload =~ /syntax_error_converting_the_varchar_value_'(.*[^+]\S+)_to_a_column_of_data_type/;
$dato=$1;
$accion="Extraccion de Informacion";
#@datos[$ind] = $dato;
$ind = $ind +1;
&historial ($accion, $sip, $fecha, $hora, $dato);
}

#Ejecucion de comandos tipo 1: "osql y OPENROWSET"
elsif ( $linexx =~ /osql/ && $linexx =~ /200/ && $linexx =~ /xp_cmdshell/ && $linexx =~ /create/)
{
$payload =~ /create table\s+(\S+)\.\.(\S+)\s+.+/;
$base=$1;
$tabla=$2;
$accion="Comando: creacion de tabla a traves de osql";
#@datos[$ind] = $dato;
$ind = $ind +1;
&historial1 ($accion, $sip, $fecha, $hora, $base, $tabla);
}

#Ejecucion de comandos tipo 1 (continuacion): "osql y OPENROWSET"
elsif ( $linexx =~ /openrowset/ && $linexx =~ /insert/ && $linexx =~ /xp_cmdshell/ && $linexx =~ /200/)
{
$payload =~ /xp_cmdshell\s+(.+)/;
$comm=$1;
$accion="Comando: insercion de datos de salida de comando shell en tabla";
#@datos[$ind] = $dato;
$ind = $ind +1;
&historial2 ($accion, $sip, $fecha, $hora, $comm);
}

#Ejecucion de comandos tipo 2: "creacion, comando e insercion en una solalinea. (Extraccion CASE)"
elsif ( $linexx =~ /create/ && $linexx =~ /insert/ && $linexx =~ /master.dbo/ && $linexx =~ /xp_cmdshell/ && $linexx =~ /200/)
{
#$payload =~ /create table\s+(\S+)\(/;
$payload =~ /create table\s+(\S+)\((.+)master.dbo.xp_cmdshell(.+)'/;
$tabla=$1;
$comm=$3;
$accion="Comando: creacion de tabla y ejecucion de comando shell con insercion de datos.";
#@datos[$ind] = $dato;
$ind = $ind +1;
&historial3 ($accion, $sip, $fecha, $hora, $tabla, $comm);
}
else {;}
}

#fin detecta()
}




sub historial ($accion, $sip, $fecha, $hora, $dato)
{
#print "XXX-H --> me llamaron con $sip.\n";
$file= "$direc" . "/" . "$sip" . ".log";
$plain= "$direc" . "/" . "$sip" ."_plain" . ".log";

if (-e "$file")
{
open(LFL, ">>$file") or die "NO es posible crear archivo de logs $file: $!";
print LFL "----------------------------------------------------------------\n";
print LFL "Accion:.............$accion.\n";
print LFL "Origen:.............$sip.\n";
print LFL "Fecha:..............$fecha.\n";
print LFL "Hora:...............$hora.\n";
print LFL "Datos:..............$dato.\n";
print LFL "\n";
}
else 
{
open(LFL, ">$file") or die "NO es posible crear archivo de logs $txt: $!";
print LFL "----------------------------------------------------------------\n";
print LFL "Accion:.............$accion.\n";
print LFL "Origen:.............$sip.\n";
print LFL "Fecha:..............$fecha.\n";
print LFL "Hora:...............$hora.\n";
print LFL "Datos:..............$dato.\n";
print LFL"\n";
}


if (-e "$plain")
{
open(XXX, ">>$plain") or die "NO es posible crear archivo de logs $file: $!";
print XXX "EXTR:   $dato.\n";
}
else
{
open(XXX, ">$plain") or die "NO es posible crear archivo de logs $file: $!";
print XXX "EXTR:   $dato.\n";
}

close (LFL);
close (XXX);
}




sub historial1 ($accion, $sip, $fecha, $hora, $base, $tabla)
{
$file= "$direc" . "/" . "$sip" . ".log";
$plain= "$direc" . "/" . "$sip" ."_plain" . ".log";

if (-e "$file")
{
open(LFL, ">>$file") or die "NO es posible crear archivo de logs $file: $!";
print LFL "----------------------------------------------------------------\n";
print LFL "Accion:.............$accion.\n";
print LFL "Origen:.............$sip.\n";
print LFL "Fecha:..............$fecha.\n";
print LFL "Hora:...............$hora.\n";
print LFL "Resultado: creacion de tabla:$tabla, en la BD:$base.\n";
print LFL "\n";
}
else
{
open(LFL, ">$file") or die "NO es posible crear archivo de logs $txt: $!";
print LFL "----------------------------------------------------------------\n";
print LFL "Accion:.............$accion.\n";
print LFL "Origen:.............$sip.\n";
print LFL "Fecha:..............$fecha.\n";
print LFL "Hora:...............$hora.\n";
print LFL "Resultado: creacion de tabla:$tabla, en la BD: $base.\n";
print LFL"\n";
}

if (-e "$plain")
{
open(XXX, ">>$plain") or die "NO es posible crear archivo de logs $file: $!";
print XXX "COMM:   Creacion de tabla: [$tabla], en la BD: [$base].\n";
}
else 
{
open(XXX, ">$plain") or die "NO es posible crear archivo de logs $file: $!";
print XXX "COMM:   Creacion de tabla: [$tabla], en la BD: [$base].\n";
}

close (LFL);
close (XXX);
}


sub historial2 ($accion, $sip, $fecha, $hora, $comm)
{
$file= "$direc" . "/" . "$sip" . ".log";
$plain= "$direc" . "/" . "$sip" ."_plain" . ".log";

if (-e "$file")
{
open(LFL, ">>$file") or die "NO es posible crear archivo de logs $file: $!";
print LFL "----------------------------------------------------------------\n";
print LFL "Accion:.............$accion.\n";
print LFL "Origen:.............$sip.\n";
print LFL "Fecha:..............$fecha.\n";
print LFL "Hora:...............$hora.\n";
print LFL "Resultado: ejecuci{on de comando de shell:$comm.\n";
print LFL "\n";
}
else
{
open(LFL, ">$file") or die "NO es posible crear archivo de logs $txt: $!";
print LFL "----------------------------------------------------------------\n";
print LFL "Accion:.............$accion.\n";
print LFL "Origen:.............$sip.\n";
print LFL "Fecha:..............$fecha.\n";
print LFL "Hora:...............$hora.\n";
print LFL "Resultado: ejecuci{on de comando de shell:$comm.\n";
print LFL"\n";
}

if (-e "$plain")
{
open(XXX, ">>$plain") or die "NO es posible crear archivo de logs $file: $!";
print XXX "COMM:   Ejecucion de comando shell: [$comm].\n";
}
else 
{
open(XXX, ">$plain") or die "NO es posible crear archivo de logs $file: $!";
print XXX "COMM:   Ejecucion de comando shell: [$comm].\n";
}

close (LFL);
close (XXX);
}


sub historial3 ($accion, $sip, $fecha, $hora, $tabla, $comm)
{
$file= "$direc" . "/" . "$sip" . ".log";
$plain= "$direc" . "/" . "$sip" ."_plain" . ".log";

if (-e "$file")
{
open(LFL, ">>$file") or die "NO es posible crear archivo de logs $file: $!";
print LFL "----------------------------------------------------------------\n";
print LFL "Accion:.............$accion.\n";
print LFL "Origen:.............$sip.\n";
print LFL "Fecha:..............$fecha.\n";
print LFL "Hora:...............$hora.\n";
print LFL "Resultado: se ha creado la tabla:$tabla.\n";
print LFL "Resultado: se ha ejecutado el comando de shell:$comm.\n";
print LFL "\n";
}
else
{
open(LFL, ">$file") or die "NO es posible crear archivo de logs $txt: $!";
print LFL "----------------------------------------------------------------\n";
print LFL "Accion:.............$accion.\n";
print LFL "Origen:.............$sip.\n";
print LFL "Fecha:..............$fecha.\n";
print LFL "Hora:...............$hora.\n";
print LFL "Resultado: se ha creado la tabla:$tabla.\n";
print LFL "Resultado: se ha ejecutado el comando de shell:$comm.\n";
print LFL"\n";
}

if (-e "$plain")
{
open(XXX, ">>$plain") or die "NO es posible crear archivo de logs $file: $!";
print XXX "COMM:   Se creo la tabla: [$tabla].\n";
print XXX "COMM:   Se ejecuto el comando shell: [$comm].\n";
}
else 
{
open(XXX, ">$plain") or die "NO es posible crear archivo de logs $file: $!";
print XXX "COMM:   Se creo la tabla: [$tabla].\n";
print XXX "COMM:   Se ejecuto el comando shell: [$comm].\n";
}

close (LFL);
close (XXX);
}


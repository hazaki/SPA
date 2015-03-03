#include <stdlib.h>
#include <stdio.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>

int asprintf(char **path, const char *format, ...);

xmlNodePtr add_client(char * ip,char * seed);

void afficher_noeud(xmlNodePtr noeud);

void delete_node(xmlDocPtr doc, char * ip);

char * getSeed(xmlDocPtr doc, char * ip);

char * getCount(xmlDocPtr doc, char * ip);

void setCountValue(xmlDocPtr doc, char * ip, char * newValue);


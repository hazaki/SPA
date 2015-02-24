#include "handle_XML_connection_file.h"

typedef void (*fct_parcours_t)(xmlNodePtr);

int asprintf(char **path, const char *format, ...) {
    int n, size = 128;
    char *np;
    va_list ap;

    if (NULL == (*path = malloc(size))) {
        return -1;
    }
    while (1) {
        va_start(ap, format);
        n = vsnprintf(*path, size, format, ap);
        va_end(ap);
        if (n > -1 && n < size) {
            return n;
        }
        if (n > -1) {
            size = n + 1;
        } else {
            size *= 2;
        }
        if (NULL == (np = realloc(*path, size))) {
            free(*path);
            return -1;
        } else {
            *path = np;
        }
    }
}

xmlNodePtr add_client(char * ip,char * seed){

  xmlNodePtr noeud_client;
  
  //creating new client node
  if ((noeud_client = xmlNewNode(NULL, BAD_CAST "client")) == NULL) {
    return NULL;
  }
  
  // add ip value to the new client node
  if (xmlSetProp(noeud_client, BAD_CAST "IP", BAD_CAST ip) == NULL) {
        xmlFreeNode(noeud_client);
        return NULL;
    }
 
  // add seed value to the new clieNt node
  if (xmlNewTextChild(noeud_client, NULL,
  		      BAD_CAST "seedPass", BAD_CAST seed) == NULL) {
    xmlFreeNode(noeud_client);
    return NULL;
  }

  //add count value to the new client_node
  if (xmlNewTextChild(noeud_client, NULL,
		      BAD_CAST "count", BAD_CAST "0") == NULL) {
    xmlFreeNode(noeud_client);
    return NULL;
  }
  
  return noeud_client;
}



void afficher_noeud(xmlNodePtr noeud) {
    if (noeud->type == XML_ELEMENT_NODE) {
        xmlChar *chemin = xmlGetNodePath(noeud);
        if (noeud->children != NULL && noeud->children->type == XML_TEXT_NODE) {
            xmlChar *contenu = xmlNodeGetContent(noeud);
            printf("%s -> %s\n", chemin, contenu);
            xmlFree(contenu);
        } else {
            printf("%s\n", chemin);
        }
        xmlFree(chemin);
    }
}

xmlNodePtr getNodeByIp(xmlDocPtr doc ,const char * ip){
  char *path;
  xmlNodePtr n = NULL;
  xmlXPathContextPtr ctxt;
  xmlXPathObjectPtr xpathRes;

  xmlXPathInit();
  ctxt = xmlXPathNewContext(doc);
  if (-1 == asprintf(&path, "/connections/client[@ip=\"%s\"]", ip)) {
    fprintf(stderr, "asprintf failed\n");
    return NULL;
  }
  printf("path %s\n", path);
  if (NULL != ctxt && NULL != path) {
    printf("ok\n");
    if (NULL != (xpathRes = xmlXPathEvalExpression(BAD_CAST path, ctxt)) &&
	XPATH_NODESET == xpathRes->type &&
	1 == xpathRes->nodesetval->nodeNr) {
      if(NULL == xmlXPathEvalExpression(BAD_CAST path, ctxt))
	printf("xmlxpatcheval error\n");
      if(XPATH_NODESET != xpathRes->type)
	printf("error type\n");
      if(1 != xpathRes->nodesetval->nodeNr)
	printf("error\n");
      n = xpathRes->nodesetval->nodeTab[0];
    }
    free(path);
    xmlXPathFreeObject(xpathRes);
    xmlXPathFreeContext(ctxt);
  }
  
  return n;
}


int main(){
  xmlDocPtr doc;
  xmlNodePtr racine;
  xmlKeepBlanksDefault(0); // Ignore les noeuds texte composant la mise en forme
  
  // open xml file
  doc = xmlParseFile("connections.xml");
  if (doc == NULL) {
    fprintf(stderr, "Invalid XML file\n");
    return EXIT_FAILURE;
  }
  // get root
  racine = xmlDocGetRootElement(doc);
  if (racine == NULL) {
    fprintf(stderr, "Empty XML file\n");
    xmlFreeDoc(doc);
    return EXIT_FAILURE;
  }
  xmlNodePtr res = getNodeByIp(doc,"IP2");
  afficher_noeud(res);
  
  //writting in XML file
  FILE* file = NULL;
  file = fopen("connections.xml", "w");
  if(file== NULL){
     fprintf(stderr, "Error while opening file\n");
  }
  xmlDocDump(file, doc);
  
  fclose(file);

  // free memory
  xmlFreeDoc(doc);

  return EXIT_SUCCESS;
}

/*
gcc -o handle_XML `xml2-config --cflags` handle_XML_connection_file.c `xml2-config --libs`
*/


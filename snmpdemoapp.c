/*
NAME: NAOMI CAMPBELL
DATE: 11/13/17
*/

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
//global scope
netsnmp_session session, *ss;
netsnmp_pdu *pdu;
netsnmp_pdu *response;
int theTime;
int numSamples;
char* agentIP;
char* community;
oid anOID[MAX_OID_LEN]; //discover device oid
size_t anOID_len; //discover device oid
oid anOID0[MAX_OID_LEN]; //added for # interfaces
size_t anOID0_len; //added for # interfaces
oid anOID3[MAX_OID_LEN]; //added for getting neighbors
size_t anOID3_len; //added for getting neighbors
netsnmp_variable_list *vars;
int status;
int count=1;
unsigned long numInterfaces;

//function declarations before main:
void begin();
void startsesh();
void closesesh();
void getNumInterfaces();
void getNeighbors();
void getNext();

//main method
int main(int argc, char ** argv)
{
    if (argc != 5) {
        printf("requirements: interval btwn samples, # samples to take, agent IP, community");
        exit(1);
    }
    theTime = atoi(argv[1]);
    numSamples = atoi(argv[2]);
    agentIP = argv[3];
    community = argv[4];
    begin();
}

void startsesh(){
    SOCK_STARTUP;
    ss = snmp_open(&session); //establish the session
    
    if (!ss) { //if session fails to open properly, print error message & exit
        snmp_sess_perror("ack", &session);
        SOCK_CLEANUP;
        exit(1);
    }
}

void closesesh(){
    //free response & close the session so can reopen
    if(response)
        snmp_free_pdu(response);
    snmp_close(ss);
    SOCK_CLEANUP;
}

void getNumInterfaces(){
    startsesh();
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    //FOR GETTING NUMBER OF INTERFACES ON THE DEVICE
    //SETS numInterfaces USED IN MAIN FOR LOOP
    anOID0_len = MAX_OID_LEN;
    if (!get_node("ifNumber.0", anOID0, &anOID0_len)){
        snmp_perror("ifNumber.0");
        SOCK_CLEANUP;
        exit(1);
    }
    snmp_add_null_var(pdu, anOID0, anOID0_len);
    //send the request out
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
        //RETRIEVE THE # VALUE OF NUM OF INTERFACES
        vars = response->variables;
        numInterfaces = vars->val.counter64->high;
        printf("-------------------------------------------------------\n\n");
        printf("\nNumber of device interfaces: %lu.\n", numInterfaces);
    }else {
        /*
         * FAILURE: print what went wrong!
         */
        
        if (status == STAT_SUCCESS)
            fprintf(stderr, "Error in packet\nReason: %s\n",
                    snmp_errstring(response->errstat));
        else if (status == STAT_TIMEOUT)
            fprintf(stderr, "Timeout: No response from %s.\n",
                    session.peername);
        else
            snmp_sess_perror("snmpdemoapp", ss);
        
    }
    closesesh();
}

void getNeighbors(){
    startsesh();
    pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
    pdu->non_repeaters = 0;
    pdu->max_repetitions = 20;
    //FOR GETTING NEIGHBORS use ipNetToPhysicalPhysAddress (returns neighboring IP addresses of device)
    anOID3_len = MAX_OID_LEN;
    if (!read_objid(".1.3.6.1.2.1.4.35.1.4", anOID3, &anOID3_len)){
        snmp_perror(".1.3.6.1.2.1.4.35.1.4");
        SOCK_CLEANUP;
        exit(1);
    }
    snmp_add_null_var(pdu, anOID3, anOID3_len);
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
        printf("\nPrinting neighboring IP addresses of device...\n\n");
        printf("-------------------------------------------------------\n\n");
        //unmanipulated data
        //for(vars = response->variables; vars; vars = vars->next_variable)
        //    print_variable(vars->name, vars->name_length, vars);
        for(vars = response->variables; vars; vars=vars->next_variable){
         if(vars->type == ASN_OCTET_STR){ //only print if string
             printf("Printing neighbor: ");
             print_variable(vars->name, vars->name_length, vars);
         }
         }
    }else {
        /*
         * FAILURE: print what went wrong!
         */
        
        if (status == STAT_SUCCESS)
            fprintf(stderr, "Error in packet\nReason: %s\n",
                    snmp_errstring(response->errstat));
        else if (status == STAT_TIMEOUT)
            fprintf(stderr, "Timeout: No response from %s.\n",
                    session.peername);
        else
            snmp_sess_perror("snmpdemoapp", ss);
        
    }
    closesesh();
}

void getNext(char* oid){
    startsesh();
    pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
    anOID_len = MAX_OID_LEN;
    get_node(oid, anOID, &anOID_len);
    //printf("PRINTING THE OID: %s\n", oid); //TEST PRINT; SEE WHAT OID IS
    snmp_add_null_var(pdu, anOID, anOID_len);
    status = snmp_synch_response(ss, pdu, &response);
    //closesesh();
}

void begin(){
    //Initialize the SNMP library
    init_snmp("snmpdemoapp");
    //Initialize a "session" that defines who we're going to talk to
    snmp_sess_init( &session ); //set up defaults
    session.peername = strdup(agentIP); //"192.168.1.83"
    /* we'll use the insecure (but simplier) SNMPv1
    
    set the SNMP version number */
    session.version = SNMP_VERSION_2c; //or just SNMP_VERSION_1 but want get bulk from v2
    
    //set the SNMPv1 community name used for authentication
    session.community = "public";
    session.community_len = strlen(session.community);
    
    //first get device IP neighbors in bulk
    getNeighbors();
    getNumInterfaces();
    //DEVICE INTERFACES, START WITH TABLE OID
    char oidInterfaces[100] = "ifPhysAddress"; //device interfaces' IP addresses, ifPhysAddress
    char oidIn[100] = "ifInOctets"; //traffic in
    char oidOut[100] = "ifOutOctets"; //traffic out
    //char oidStats[100] = "ifSpeed"; //get speed of interfaces, ifSpeed
    //SELF NOTE: GOT BUFFER OVERFLOW WHEN DIDN'T HAVE VALUE IN CHAR BRACKETS!

    int i = 1; //for for loop
    printf("\n------ PRINTING DEVICE INTERFACE IP's AND INCOMING & OUTGOING TRAFFIC ------\n");
    for(i; i <= numSamples; i++){
        printf("\nSAMPLE #%d\n\n", i);
        int j = 0;
        for(j; j < numInterfaces; j++){ //e.g. if there are 5 devices, loop through all 5 to get IP + stats
            //anOID for interface # and IP
            getNext(oidInterfaces);
            if(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR){
                for(vars = response->variables; vars; vars=vars->next_variable){
                    if(vars->type == ASN_OCTET_STR){
                        printf("Device interface #%d:\n", count);
                        print_variable(vars->name, vars->name_length, vars);
                    }
                }
                //for(vars = response->variables; vars; vars = vars->next_variable)
                    //print_variable(vars->name, vars->name_length, vars);
                vars = response->variables;
                char tmp[100];
                snprint_objid(tmp, 100, vars->name, vars->name_length);
                strcpy(oidInterfaces,tmp);
            }else {
                if (status == STAT_SUCCESS)
                    fprintf(stderr, "Error in packet\nReason: %s\n",
                            snmp_errstring(response->errstat));
                else
                    snmp_sess_perror("snmpget", ss);
            }
            closesesh(); //close sesh for the statistics next
            
            //-------------do the same thing below as above for traffic in-----------
            getNext(oidIn);
            if(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR){
                for(vars = response->variables; vars; vars=vars->next_variable){
                    if(vars->type == ASN_COUNTER){
                        printf("Interface #%d Incoming Traffic (# Octets Received): \n", count);
                        print_variable(vars->name, vars->name_length, vars);
                    }
                }
                //for(vars = response->variables; vars; vars = vars->next_variable)
                //print_variable(vars->name, vars->name_length, vars);
                vars = response->variables;
                char tmp[100];
                snprint_objid(tmp, 100, vars->name, vars->name_length);
                strcpy(oidIn,tmp);
            }else {
                if (status == STAT_SUCCESS)
                    fprintf(stderr, "Error in packet\nReason: %s\n",
                            snmp_errstring(response->errstat));
                else
                    snmp_sess_perror("snmpget", ss);
            }
            closesesh();
            
            //-------------do the same thing below as above for traffic out-----------
            getNext(oidOut);
            if(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR){
                for(vars = response->variables; vars; vars=vars->next_variable){
                    if(vars->type == ASN_COUNTER){
                        printf("Interface #%d Outgoing Traffic (# Octets Out): \n", count);
                        print_variable(vars->name, vars->name_length, vars);
                        printf("\n");
                    }
                }
                //for(vars = response->variables; vars; vars = vars->next_variable)
                //print_variable(vars->name, vars->name_length, vars);
                vars = response->variables;
                char tmp[100];
                snprint_objid(tmp, 100, vars->name, vars->name_length);
                strcpy(oidOut,tmp);
            }else {
                if (status == STAT_SUCCESS)
                    fprintf(stderr, "Error in packet\nReason: %s\n",
                            snmp_errstring(response->errstat));
                else
                    snmp_sess_perror("snmpget", ss);
            }
            closesesh(); //close sesh for next loop around
            //finally, increase interface num
            count++;
        } //END OF FOR
        count = 1; //reset interface counter for next batch of samples
        fflush(stdout);
        poll(0,0,1000); //500 - in milliseconds
        strcpy(oidInterfaces, "ifPhysAddress"); //set back to starting point
        strcpy(oidIn, "ifInOctets"); //set back to starting point
        strcpy(oidOut, "ifInOctets"); //set back to starting point

    }
}

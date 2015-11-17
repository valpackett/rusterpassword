#include <stdint.h>

typedef struct secstr_S secstr_t;

#define TEMPLATES_PIN     10
#define TEMPLATES_BASIC   20
#define TEMPLATES_SHORT   30
#define TEMPLATES_MEDIUM  40
#define TEMPLATES_LONG    50
#define TEMPLATES_MAXIMUM 60

secstr_t* rusterpassword_gen_master_key(const char*, const char*);
secstr_t* rusterpassword_gen_site_seed(const secstr_t*, const char*, uint32_t);
char* rusterpassword_gen_site_password(const secstr_t*, uint32_t);
void rusterpassword_free_master_key(secstr_t*);
void rusterpassword_free_site_seed(secstr_t*);
void rusterpassword_free_site_password(char*);

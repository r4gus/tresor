typedef enum {
    ERR_SUCCESS = 0,
    ERR_AOM = -1,
    ERR_DNE = -2,
    ERR_DE = -3,
    ERR_FILE = -4,
    ERR_SEAL = -5,
    ERR_FAIL = -6,
} TresorError;

typedef void* Tresor;
typedef void* Entry;

Tresor Tresor_new(const char* name);
void Tresor_deinit();
TresorError Tresor_entry_create(void* self, const char* id);
Entry Tresor_entry_get(void* self, const char* id);
TresorError Tresor_entry_remove(void* self, const char* id);
void** Tresor_entry_get_many(void* self, const char* filter);
TresorError Tresor_entry_filed_add(void* entry, const char* key, const char* value);
const char* Tresor_entry_field_get(void* entry, const char* key);
TresorError Tresor_entry_field_update(void* entry, const char* key, const char* value);
TresorError Tresor_seal(void* self, const char* path, const char* pw);
Tresor Tresor_open(const char* path, const char* pw);

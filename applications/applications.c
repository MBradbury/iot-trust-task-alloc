#include "applications.h"

struct process* find_process_with_name(const char* name)
{
	for (struct process* iter = PROCESS_LIST(); iter != NULL; iter = iter->next)
	{
		if (strcmp(iter->name, name) == 0)
		{
			return iter;
		}
	}

	return NULL;
}

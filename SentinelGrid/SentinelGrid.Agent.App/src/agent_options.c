#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include <utilities/agent_options.h>

int parseAgentOptions(int argc, char* argv[], AgentOptions* options) {
	if (argv == NULL || options == NULL)
		return 0;

	if (argc != 2 || argv[1] == NULL)
		return 0;

	const char* text = argv[1];
	
	if (*text == '\0')
		return 0;

	for (const char* current = text; *current != '\0'; ++current) {

		if (*current < '0' || *current > '9')
			return 0;
	}

	errno = 0;
	char* end = NULL;

	unsigned long parsed = strtoul(text, &end, 10);

	if (errno == ERANGE) 
		return 0;

	if (end == text || *end != 0)
		return 0;

	if (parsed == 0 || parsed > UINT32_MAX)
		return 0;

	options->agent_id = (uint32_t)parsed;
	return 1;
}

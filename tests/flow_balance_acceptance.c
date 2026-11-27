#include "pfring_flow_balance.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *argv0) {
  fprintf(stderr,
          "Usage: %s [--queues 4] [--flows N] [--packets N]\n"
          "          [--threshold-bps N] [--seed N] [--json PATH] [--verbose]\n",
          argv0);
}

int main(int argc, char **argv) {
  pfring_fb_acceptance_config config;
  pfring_fb_acceptance_result *result;
  const char *json_path = NULL;
  const char *distribution_json_path = NULL;
  int i;
  int rc;

  memset(&config, 0, sizeof(config));
  config.num_queues = 4;
  config.num_flows = 4096;
  config.packets_per_flow = 32;
  config.deviation_bps = PFRING_FB_DEFAULT_DEVIATION_BPS;
  config.verbose = 1;

  for(i = 1; i < argc; i++) {
    const char *arg = argv[i];

    if(strcmp(arg, "--queues") == 0 && i + 1 < argc) {
      config.num_queues = (uint32_t)strtoul(argv[++i], NULL, 10);
    } else if(strcmp(arg, "--flows") == 0 && i + 1 < argc) {
      config.num_flows = (uint32_t)strtoul(argv[++i], NULL, 10);
    } else if(strcmp(arg, "--packets") == 0 && i + 1 < argc) {
      config.packets_per_flow = (uint32_t)strtoul(argv[++i], NULL, 10);
    } else if(strcmp(arg, "--threshold-bps") == 0 && i + 1 < argc) {
      config.deviation_bps = (uint32_t)strtoul(argv[++i], NULL, 10);
    } else if(strcmp(arg, "--seed") == 0 && i + 1 < argc) {
      config.seed = (uint32_t)strtoul(argv[++i], NULL, 10);
    } else if(strcmp(arg, "--json") == 0 && i + 1 < argc) {
      json_path = argv[++i];
      config.json_path = json_path;
    } else if(strcmp(arg, "--distribution-json") == 0 && i + 1 < argc) {
      distribution_json_path = argv[++i];
    } else if(strcmp(arg, "--verbose") == 0) {
      config.verbose = 1;
    } else if(strcmp(arg, "--quiet") == 0) {
      config.verbose = 0;
    } else if(strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
      usage(argv[0]);
      return 0;
    } else {
      usage(argv[0]);
      return 2;
    }
  }

  result = calloc(1, sizeof(*result));
  if(result == NULL) {
    fprintf(stderr, "out of memory\n");
    return 2;
  }

  rc = pfring_fb_run_acceptance(&config, result);
  if(rc != PFRING_FB_OK) {
    fprintf(stderr, "acceptance setup failed: %d\n", rc);
    free(result);
    return 2;
  }

  printf("flow_balance: queues=%u total=%llu min=%llu max=%llu "
         "max_deviation_bps=%u threshold_bps=%u\n",
         result->num_queues,
         (unsigned long long)result->total_packets,
         (unsigned long long)result->min_packets,
         (unsigned long long)result->max_packets,
         result->max_deviation_bps,
         result->threshold_bps);
  printf("flow_balance: distribution=%s ordering=%s affinity=%s "
         "drop_export=%s overall=%s\n",
         result->distribution_ok ? "PASS" : "FAIL",
         result->ordering_ok ? "PASS" : "FAIL",
         result->affinity_ok ? "PASS" : "FAIL",
         result->drop_export_ok ? "PASS" : "FAIL",
         result->acceptance_ok ? "PASS" : "FAIL");

  if(json_path != NULL)
    printf("flow_balance: drop stats JSON=%s\n", json_path);

  if(distribution_json_path != NULL) {
    char *json = pfring_fb_snapshot_json(&result->snapshot);
    if(json == NULL) {
      free(result);
      return 2;
    }
    if(strcmp(distribution_json_path, "-") == 0) {
      fputs(json, stdout);
    } else {
      FILE *out = fopen(distribution_json_path, "w");
      if(out == NULL) {
        free(json);
        free(result);
        return 2;
      }
      fputs(json, out);
      fclose(out);
      printf("flow_balance: distribution stats JSON=%s\n",
             distribution_json_path);
    }
    free(json);
  }

  rc = result->acceptance_ok ? 0 : 1;
  free(result);
  return rc;
}

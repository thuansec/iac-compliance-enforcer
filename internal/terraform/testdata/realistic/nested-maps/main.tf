# Ten environments of thirty services, flattened into a map of 300 entries that resources
# look up by key: the local.m[k] pattern.
locals {
  envs = {
    dev = {
      services = {
        svc00 = { replicas = 1, cpu = 256, image = "registry.example.com/svc00:1.0" }
        svc01 = { replicas = 2, cpu = 512, image = "registry.example.com/svc01:1.1" }
        svc02 = { replicas = 3, cpu = 768, image = "registry.example.com/svc02:1.2" }
        svc03 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc03:1.3" }
        svc04 = { replicas = 2, cpu = 256, image = "registry.example.com/svc04:1.4" }
        svc05 = { replicas = 3, cpu = 512, image = "registry.example.com/svc05:1.5" }
        svc06 = { replicas = 1, cpu = 768, image = "registry.example.com/svc06:1.6" }
        svc07 = { replicas = 2, cpu = 1024, image = "registry.example.com/svc07:1.7" }
        svc08 = { replicas = 3, cpu = 256, image = "registry.example.com/svc08:1.8" }
        svc09 = { replicas = 1, cpu = 512, image = "registry.example.com/svc09:1.9" }
        svc10 = { replicas = 2, cpu = 768, image = "registry.example.com/svc10:1.10" }
        svc11 = { replicas = 3, cpu = 1024, image = "registry.example.com/svc11:1.11" }
        svc12 = { replicas = 1, cpu = 256, image = "registry.example.com/svc12:1.12" }
        svc13 = { replicas = 2, cpu = 512, image = "registry.example.com/svc13:1.13" }
        svc14 = { replicas = 3, cpu = 768, image = "registry.example.com/svc14:1.14" }
        svc15 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc15:1.15" }
        svc16 = { replicas = 2, cpu = 256, image = "registry.example.com/svc16:1.16" }
        svc17 = { replicas = 3, cpu = 512, image = "registry.example.com/svc17:1.17" }
        svc18 = { replicas = 1, cpu = 768, image = "registry.example.com/svc18:1.18" }
        svc19 = { replicas = 2, cpu = 1024, image = "registry.example.com/svc19:1.19" }
        svc20 = { replicas = 3, cpu = 256, image = "registry.example.com/svc20:1.20" }
        svc21 = { replicas = 1, cpu = 512, image = "registry.example.com/svc21:1.21" }
        svc22 = { replicas = 2, cpu = 768, image = "registry.example.com/svc22:1.22" }
        svc23 = { replicas = 3, cpu = 1024, image = "registry.example.com/svc23:1.23" }
        svc24 = { replicas = 1, cpu = 256, image = "registry.example.com/svc24:1.24" }
        svc25 = { replicas = 2, cpu = 512, image = "registry.example.com/svc25:1.25" }
        svc26 = { replicas = 3, cpu = 768, image = "registry.example.com/svc26:1.26" }
        svc27 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc27:1.27" }
        svc28 = { replicas = 2, cpu = 256, image = "registry.example.com/svc28:1.28" }
        svc29 = { replicas = 3, cpu = 512, image = "registry.example.com/svc29:1.29" }
      }
    }
    test = {
      services = {
        svc00 = { replicas = 1, cpu = 256, image = "registry.example.com/svc00:1.0" }
        svc01 = { replicas = 2, cpu = 512, image = "registry.example.com/svc01:1.1" }
        svc02 = { replicas = 3, cpu = 768, image = "registry.example.com/svc02:1.2" }
        svc03 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc03:1.3" }
        svc04 = { replicas = 2, cpu = 256, image = "registry.example.com/svc04:1.4" }
        svc05 = { replicas = 3, cpu = 512, image = "registry.example.com/svc05:1.5" }
        svc06 = { replicas = 1, cpu = 768, image = "registry.example.com/svc06:1.6" }
        svc07 = { replicas = 2, cpu = 1024, image = "registry.example.com/svc07:1.7" }
        svc08 = { replicas = 3, cpu = 256, image = "registry.example.com/svc08:1.8" }
        svc09 = { replicas = 1, cpu = 512, image = "registry.example.com/svc09:1.9" }
        svc10 = { replicas = 2, cpu = 768, image = "registry.example.com/svc10:1.10" }
        svc11 = { replicas = 3, cpu = 1024, image = "registry.example.com/svc11:1.11" }
        svc12 = { replicas = 1, cpu = 256, image = "registry.example.com/svc12:1.12" }
        svc13 = { replicas = 2, cpu = 512, image = "registry.example.com/svc13:1.13" }
        svc14 = { replicas = 3, cpu = 768, image = "registry.example.com/svc14:1.14" }
        svc15 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc15:1.15" }
        svc16 = { replicas = 2, cpu = 256, image = "registry.example.com/svc16:1.16" }
        svc17 = { replicas = 3, cpu = 512, image = "registry.example.com/svc17:1.17" }
        svc18 = { replicas = 1, cpu = 768, image = "registry.example.com/svc18:1.18" }
        svc19 = { replicas = 2, cpu = 1024, image = "registry.example.com/svc19:1.19" }
        svc20 = { replicas = 3, cpu = 256, image = "registry.example.com/svc20:1.20" }
        svc21 = { replicas = 1, cpu = 512, image = "registry.example.com/svc21:1.21" }
        svc22 = { replicas = 2, cpu = 768, image = "registry.example.com/svc22:1.22" }
        svc23 = { replicas = 3, cpu = 1024, image = "registry.example.com/svc23:1.23" }
        svc24 = { replicas = 1, cpu = 256, image = "registry.example.com/svc24:1.24" }
        svc25 = { replicas = 2, cpu = 512, image = "registry.example.com/svc25:1.25" }
        svc26 = { replicas = 3, cpu = 768, image = "registry.example.com/svc26:1.26" }
        svc27 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc27:1.27" }
        svc28 = { replicas = 2, cpu = 256, image = "registry.example.com/svc28:1.28" }
        svc29 = { replicas = 3, cpu = 512, image = "registry.example.com/svc29:1.29" }
      }
    }
    staging = {
      services = {
        svc00 = { replicas = 1, cpu = 256, image = "registry.example.com/svc00:1.0" }
        svc01 = { replicas = 2, cpu = 512, image = "registry.example.com/svc01:1.1" }
        svc02 = { replicas = 3, cpu = 768, image = "registry.example.com/svc02:1.2" }
        svc03 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc03:1.3" }
        svc04 = { replicas = 2, cpu = 256, image = "registry.example.com/svc04:1.4" }
        svc05 = { replicas = 3, cpu = 512, image = "registry.example.com/svc05:1.5" }
        svc06 = { replicas = 1, cpu = 768, image = "registry.example.com/svc06:1.6" }
        svc07 = { replicas = 2, cpu = 1024, image = "registry.example.com/svc07:1.7" }
        svc08 = { replicas = 3, cpu = 256, image = "registry.example.com/svc08:1.8" }
        svc09 = { replicas = 1, cpu = 512, image = "registry.example.com/svc09:1.9" }
        svc10 = { replicas = 2, cpu = 768, image = "registry.example.com/svc10:1.10" }
        svc11 = { replicas = 3, cpu = 1024, image = "registry.example.com/svc11:1.11" }
        svc12 = { replicas = 1, cpu = 256, image = "registry.example.com/svc12:1.12" }
        svc13 = { replicas = 2, cpu = 512, image = "registry.example.com/svc13:1.13" }
        svc14 = { replicas = 3, cpu = 768, image = "registry.example.com/svc14:1.14" }
        svc15 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc15:1.15" }
        svc16 = { replicas = 2, cpu = 256, image = "registry.example.com/svc16:1.16" }
        svc17 = { replicas = 3, cpu = 512, image = "registry.example.com/svc17:1.17" }
        svc18 = { replicas = 1, cpu = 768, image = "registry.example.com/svc18:1.18" }
        svc19 = { replicas = 2, cpu = 1024, image = "registry.example.com/svc19:1.19" }
        svc20 = { replicas = 3, cpu = 256, image = "registry.example.com/svc20:1.20" }
        svc21 = { replicas = 1, cpu = 512, image = "registry.example.com/svc21:1.21" }
        svc22 = { replicas = 2, cpu = 768, image = "registry.example.com/svc22:1.22" }
        svc23 = { replicas = 3, cpu = 1024, image = "registry.example.com/svc23:1.23" }
        svc24 = { replicas = 1, cpu = 256, image = "registry.example.com/svc24:1.24" }
        svc25 = { replicas = 2, cpu = 512, image = "registry.example.com/svc25:1.25" }
        svc26 = { replicas = 3, cpu = 768, image = "registry.example.com/svc26:1.26" }
        svc27 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc27:1.27" }
        svc28 = { replicas = 2, cpu = 256, image = "registry.example.com/svc28:1.28" }
        svc29 = { replicas = 3, cpu = 512, image = "registry.example.com/svc29:1.29" }
      }
    }
    prod = {
      services = {
        svc00 = { replicas = 1, cpu = 256, image = "registry.example.com/svc00:1.0" }
        svc01 = { replicas = 2, cpu = 512, image = "registry.example.com/svc01:1.1" }
        svc02 = { replicas = 3, cpu = 768, image = "registry.example.com/svc02:1.2" }
        svc03 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc03:1.3" }
        svc04 = { replicas = 2, cpu = 256, image = "registry.example.com/svc04:1.4" }
        svc05 = { replicas = 3, cpu = 512, image = "registry.example.com/svc05:1.5" }
        svc06 = { replicas = 1, cpu = 768, image = "registry.example.com/svc06:1.6" }
        svc07 = { replicas = 2, cpu = 1024, image = "registry.example.com/svc07:1.7" }
        svc08 = { replicas = 3, cpu = 256, image = "registry.example.com/svc08:1.8" }
        svc09 = { replicas = 1, cpu = 512, image = "registry.example.com/svc09:1.9" }
        svc10 = { replicas = 2, cpu = 768, image = "registry.example.com/svc10:1.10" }
        svc11 = { replicas = 3, cpu = 1024, image = "registry.example.com/svc11:1.11" }
        svc12 = { replicas = 1, cpu = 256, image = "registry.example.com/svc12:1.12" }
        svc13 = { replicas = 2, cpu = 512, image = "registry.example.com/svc13:1.13" }
        svc14 = { replicas = 3, cpu = 768, image = "registry.example.com/svc14:1.14" }
        svc15 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc15:1.15" }
        svc16 = { replicas = 2, cpu = 256, image = "registry.example.com/svc16:1.16" }
        svc17 = { replicas = 3, cpu = 512, image = "registry.example.com/svc17:1.17" }
        svc18 = { replicas = 1, cpu = 768, image = "registry.example.com/svc18:1.18" }
        svc19 = { replicas = 2, cpu = 1024, image = "registry.example.com/svc19:1.19" }
        svc20 = { replicas = 3, cpu = 256, image = "registry.example.com/svc20:1.20" }
        svc21 = { replicas = 1, cpu = 512, image = "registry.example.com/svc21:1.21" }
        svc22 = { replicas = 2, cpu = 768, image = "registry.example.com/svc22:1.22" }
        svc23 = { replicas = 3, cpu = 1024, image = "registry.example.com/svc23:1.23" }
        svc24 = { replicas = 1, cpu = 256, image = "registry.example.com/svc24:1.24" }
        svc25 = { replicas = 2, cpu = 512, image = "registry.example.com/svc25:1.25" }
        svc26 = { replicas = 3, cpu = 768, image = "registry.example.com/svc26:1.26" }
        svc27 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc27:1.27" }
        svc28 = { replicas = 2, cpu = 256, image = "registry.example.com/svc28:1.28" }
        svc29 = { replicas = 3, cpu = 512, image = "registry.example.com/svc29:1.29" }
      }
    }
    perf = {
      services = {
        svc00 = { replicas = 1, cpu = 256, image = "registry.example.com/svc00:1.0" }
        svc01 = { replicas = 2, cpu = 512, image = "registry.example.com/svc01:1.1" }
        svc02 = { replicas = 3, cpu = 768, image = "registry.example.com/svc02:1.2" }
        svc03 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc03:1.3" }
        svc04 = { replicas = 2, cpu = 256, image = "registry.example.com/svc04:1.4" }
        svc05 = { replicas = 3, cpu = 512, image = "registry.example.com/svc05:1.5" }
        svc06 = { replicas = 1, cpu = 768, image = "registry.example.com/svc06:1.6" }
        svc07 = { replicas = 2, cpu = 1024, image = "registry.example.com/svc07:1.7" }
        svc08 = { replicas = 3, cpu = 256, image = "registry.example.com/svc08:1.8" }
        svc09 = { replicas = 1, cpu = 512, image = "registry.example.com/svc09:1.9" }
        svc10 = { replicas = 2, cpu = 768, image = "registry.example.com/svc10:1.10" }
        svc11 = { replicas = 3, cpu = 1024, image = "registry.example.com/svc11:1.11" }
        svc12 = { replicas = 1, cpu = 256, image = "registry.example.com/svc12:1.12" }
        svc13 = { replicas = 2, cpu = 512, image = "registry.example.com/svc13:1.13" }
        svc14 = { replicas = 3, cpu = 768, image = "registry.example.com/svc14:1.14" }
        svc15 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc15:1.15" }
        svc16 = { replicas = 2, cpu = 256, image = "registry.example.com/svc16:1.16" }
        svc17 = { replicas = 3, cpu = 512, image = "registry.example.com/svc17:1.17" }
        svc18 = { replicas = 1, cpu = 768, image = "registry.example.com/svc18:1.18" }
        svc19 = { replicas = 2, cpu = 1024, image = "registry.example.com/svc19:1.19" }
        svc20 = { replicas = 3, cpu = 256, image = "registry.example.com/svc20:1.20" }
        svc21 = { replicas = 1, cpu = 512, image = "registry.example.com/svc21:1.21" }
        svc22 = { replicas = 2, cpu = 768, image = "registry.example.com/svc22:1.22" }
        svc23 = { replicas = 3, cpu = 1024, image = "registry.example.com/svc23:1.23" }
        svc24 = { replicas = 1, cpu = 256, image = "registry.example.com/svc24:1.24" }
        svc25 = { replicas = 2, cpu = 512, image = "registry.example.com/svc25:1.25" }
        svc26 = { replicas = 3, cpu = 768, image = "registry.example.com/svc26:1.26" }
        svc27 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc27:1.27" }
        svc28 = { replicas = 2, cpu = 256, image = "registry.example.com/svc28:1.28" }
        svc29 = { replicas = 3, cpu = 512, image = "registry.example.com/svc29:1.29" }
      }
    }
    sandbox = {
      services = {
        svc00 = { replicas = 1, cpu = 256, image = "registry.example.com/svc00:1.0" }
        svc01 = { replicas = 2, cpu = 512, image = "registry.example.com/svc01:1.1" }
        svc02 = { replicas = 3, cpu = 768, image = "registry.example.com/svc02:1.2" }
        svc03 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc03:1.3" }
        svc04 = { replicas = 2, cpu = 256, image = "registry.example.com/svc04:1.4" }
        svc05 = { replicas = 3, cpu = 512, image = "registry.example.com/svc05:1.5" }
        svc06 = { replicas = 1, cpu = 768, image = "registry.example.com/svc06:1.6" }
        svc07 = { replicas = 2, cpu = 1024, image = "registry.example.com/svc07:1.7" }
        svc08 = { replicas = 3, cpu = 256, image = "registry.example.com/svc08:1.8" }
        svc09 = { replicas = 1, cpu = 512, image = "registry.example.com/svc09:1.9" }
        svc10 = { replicas = 2, cpu = 768, image = "registry.example.com/svc10:1.10" }
        svc11 = { replicas = 3, cpu = 1024, image = "registry.example.com/svc11:1.11" }
        svc12 = { replicas = 1, cpu = 256, image = "registry.example.com/svc12:1.12" }
        svc13 = { replicas = 2, cpu = 512, image = "registry.example.com/svc13:1.13" }
        svc14 = { replicas = 3, cpu = 768, image = "registry.example.com/svc14:1.14" }
        svc15 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc15:1.15" }
        svc16 = { replicas = 2, cpu = 256, image = "registry.example.com/svc16:1.16" }
        svc17 = { replicas = 3, cpu = 512, image = "registry.example.com/svc17:1.17" }
        svc18 = { replicas = 1, cpu = 768, image = "registry.example.com/svc18:1.18" }
        svc19 = { replicas = 2, cpu = 1024, image = "registry.example.com/svc19:1.19" }
        svc20 = { replicas = 3, cpu = 256, image = "registry.example.com/svc20:1.20" }
        svc21 = { replicas = 1, cpu = 512, image = "registry.example.com/svc21:1.21" }
        svc22 = { replicas = 2, cpu = 768, image = "registry.example.com/svc22:1.22" }
        svc23 = { replicas = 3, cpu = 1024, image = "registry.example.com/svc23:1.23" }
        svc24 = { replicas = 1, cpu = 256, image = "registry.example.com/svc24:1.24" }
        svc25 = { replicas = 2, cpu = 512, image = "registry.example.com/svc25:1.25" }
        svc26 = { replicas = 3, cpu = 768, image = "registry.example.com/svc26:1.26" }
        svc27 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc27:1.27" }
        svc28 = { replicas = 2, cpu = 256, image = "registry.example.com/svc28:1.28" }
        svc29 = { replicas = 3, cpu = 512, image = "registry.example.com/svc29:1.29" }
      }
    }
    dr = {
      services = {
        svc00 = { replicas = 1, cpu = 256, image = "registry.example.com/svc00:1.0" }
        svc01 = { replicas = 2, cpu = 512, image = "registry.example.com/svc01:1.1" }
        svc02 = { replicas = 3, cpu = 768, image = "registry.example.com/svc02:1.2" }
        svc03 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc03:1.3" }
        svc04 = { replicas = 2, cpu = 256, image = "registry.example.com/svc04:1.4" }
        svc05 = { replicas = 3, cpu = 512, image = "registry.example.com/svc05:1.5" }
        svc06 = { replicas = 1, cpu = 768, image = "registry.example.com/svc06:1.6" }
        svc07 = { replicas = 2, cpu = 1024, image = "registry.example.com/svc07:1.7" }
        svc08 = { replicas = 3, cpu = 256, image = "registry.example.com/svc08:1.8" }
        svc09 = { replicas = 1, cpu = 512, image = "registry.example.com/svc09:1.9" }
        svc10 = { replicas = 2, cpu = 768, image = "registry.example.com/svc10:1.10" }
        svc11 = { replicas = 3, cpu = 1024, image = "registry.example.com/svc11:1.11" }
        svc12 = { replicas = 1, cpu = 256, image = "registry.example.com/svc12:1.12" }
        svc13 = { replicas = 2, cpu = 512, image = "registry.example.com/svc13:1.13" }
        svc14 = { replicas = 3, cpu = 768, image = "registry.example.com/svc14:1.14" }
        svc15 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc15:1.15" }
        svc16 = { replicas = 2, cpu = 256, image = "registry.example.com/svc16:1.16" }
        svc17 = { replicas = 3, cpu = 512, image = "registry.example.com/svc17:1.17" }
        svc18 = { replicas = 1, cpu = 768, image = "registry.example.com/svc18:1.18" }
        svc19 = { replicas = 2, cpu = 1024, image = "registry.example.com/svc19:1.19" }
        svc20 = { replicas = 3, cpu = 256, image = "registry.example.com/svc20:1.20" }
        svc21 = { replicas = 1, cpu = 512, image = "registry.example.com/svc21:1.21" }
        svc22 = { replicas = 2, cpu = 768, image = "registry.example.com/svc22:1.22" }
        svc23 = { replicas = 3, cpu = 1024, image = "registry.example.com/svc23:1.23" }
        svc24 = { replicas = 1, cpu = 256, image = "registry.example.com/svc24:1.24" }
        svc25 = { replicas = 2, cpu = 512, image = "registry.example.com/svc25:1.25" }
        svc26 = { replicas = 3, cpu = 768, image = "registry.example.com/svc26:1.26" }
        svc27 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc27:1.27" }
        svc28 = { replicas = 2, cpu = 256, image = "registry.example.com/svc28:1.28" }
        svc29 = { replicas = 3, cpu = 512, image = "registry.example.com/svc29:1.29" }
      }
    }
    qa = {
      services = {
        svc00 = { replicas = 1, cpu = 256, image = "registry.example.com/svc00:1.0" }
        svc01 = { replicas = 2, cpu = 512, image = "registry.example.com/svc01:1.1" }
        svc02 = { replicas = 3, cpu = 768, image = "registry.example.com/svc02:1.2" }
        svc03 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc03:1.3" }
        svc04 = { replicas = 2, cpu = 256, image = "registry.example.com/svc04:1.4" }
        svc05 = { replicas = 3, cpu = 512, image = "registry.example.com/svc05:1.5" }
        svc06 = { replicas = 1, cpu = 768, image = "registry.example.com/svc06:1.6" }
        svc07 = { replicas = 2, cpu = 1024, image = "registry.example.com/svc07:1.7" }
        svc08 = { replicas = 3, cpu = 256, image = "registry.example.com/svc08:1.8" }
        svc09 = { replicas = 1, cpu = 512, image = "registry.example.com/svc09:1.9" }
        svc10 = { replicas = 2, cpu = 768, image = "registry.example.com/svc10:1.10" }
        svc11 = { replicas = 3, cpu = 1024, image = "registry.example.com/svc11:1.11" }
        svc12 = { replicas = 1, cpu = 256, image = "registry.example.com/svc12:1.12" }
        svc13 = { replicas = 2, cpu = 512, image = "registry.example.com/svc13:1.13" }
        svc14 = { replicas = 3, cpu = 768, image = "registry.example.com/svc14:1.14" }
        svc15 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc15:1.15" }
        svc16 = { replicas = 2, cpu = 256, image = "registry.example.com/svc16:1.16" }
        svc17 = { replicas = 3, cpu = 512, image = "registry.example.com/svc17:1.17" }
        svc18 = { replicas = 1, cpu = 768, image = "registry.example.com/svc18:1.18" }
        svc19 = { replicas = 2, cpu = 1024, image = "registry.example.com/svc19:1.19" }
        svc20 = { replicas = 3, cpu = 256, image = "registry.example.com/svc20:1.20" }
        svc21 = { replicas = 1, cpu = 512, image = "registry.example.com/svc21:1.21" }
        svc22 = { replicas = 2, cpu = 768, image = "registry.example.com/svc22:1.22" }
        svc23 = { replicas = 3, cpu = 1024, image = "registry.example.com/svc23:1.23" }
        svc24 = { replicas = 1, cpu = 256, image = "registry.example.com/svc24:1.24" }
        svc25 = { replicas = 2, cpu = 512, image = "registry.example.com/svc25:1.25" }
        svc26 = { replicas = 3, cpu = 768, image = "registry.example.com/svc26:1.26" }
        svc27 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc27:1.27" }
        svc28 = { replicas = 2, cpu = 256, image = "registry.example.com/svc28:1.28" }
        svc29 = { replicas = 3, cpu = 512, image = "registry.example.com/svc29:1.29" }
      }
    }
    uat = {
      services = {
        svc00 = { replicas = 1, cpu = 256, image = "registry.example.com/svc00:1.0" }
        svc01 = { replicas = 2, cpu = 512, image = "registry.example.com/svc01:1.1" }
        svc02 = { replicas = 3, cpu = 768, image = "registry.example.com/svc02:1.2" }
        svc03 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc03:1.3" }
        svc04 = { replicas = 2, cpu = 256, image = "registry.example.com/svc04:1.4" }
        svc05 = { replicas = 3, cpu = 512, image = "registry.example.com/svc05:1.5" }
        svc06 = { replicas = 1, cpu = 768, image = "registry.example.com/svc06:1.6" }
        svc07 = { replicas = 2, cpu = 1024, image = "registry.example.com/svc07:1.7" }
        svc08 = { replicas = 3, cpu = 256, image = "registry.example.com/svc08:1.8" }
        svc09 = { replicas = 1, cpu = 512, image = "registry.example.com/svc09:1.9" }
        svc10 = { replicas = 2, cpu = 768, image = "registry.example.com/svc10:1.10" }
        svc11 = { replicas = 3, cpu = 1024, image = "registry.example.com/svc11:1.11" }
        svc12 = { replicas = 1, cpu = 256, image = "registry.example.com/svc12:1.12" }
        svc13 = { replicas = 2, cpu = 512, image = "registry.example.com/svc13:1.13" }
        svc14 = { replicas = 3, cpu = 768, image = "registry.example.com/svc14:1.14" }
        svc15 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc15:1.15" }
        svc16 = { replicas = 2, cpu = 256, image = "registry.example.com/svc16:1.16" }
        svc17 = { replicas = 3, cpu = 512, image = "registry.example.com/svc17:1.17" }
        svc18 = { replicas = 1, cpu = 768, image = "registry.example.com/svc18:1.18" }
        svc19 = { replicas = 2, cpu = 1024, image = "registry.example.com/svc19:1.19" }
        svc20 = { replicas = 3, cpu = 256, image = "registry.example.com/svc20:1.20" }
        svc21 = { replicas = 1, cpu = 512, image = "registry.example.com/svc21:1.21" }
        svc22 = { replicas = 2, cpu = 768, image = "registry.example.com/svc22:1.22" }
        svc23 = { replicas = 3, cpu = 1024, image = "registry.example.com/svc23:1.23" }
        svc24 = { replicas = 1, cpu = 256, image = "registry.example.com/svc24:1.24" }
        svc25 = { replicas = 2, cpu = 512, image = "registry.example.com/svc25:1.25" }
        svc26 = { replicas = 3, cpu = 768, image = "registry.example.com/svc26:1.26" }
        svc27 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc27:1.27" }
        svc28 = { replicas = 2, cpu = 256, image = "registry.example.com/svc28:1.28" }
        svc29 = { replicas = 3, cpu = 512, image = "registry.example.com/svc29:1.29" }
      }
    }
    demo = {
      services = {
        svc00 = { replicas = 1, cpu = 256, image = "registry.example.com/svc00:1.0" }
        svc01 = { replicas = 2, cpu = 512, image = "registry.example.com/svc01:1.1" }
        svc02 = { replicas = 3, cpu = 768, image = "registry.example.com/svc02:1.2" }
        svc03 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc03:1.3" }
        svc04 = { replicas = 2, cpu = 256, image = "registry.example.com/svc04:1.4" }
        svc05 = { replicas = 3, cpu = 512, image = "registry.example.com/svc05:1.5" }
        svc06 = { replicas = 1, cpu = 768, image = "registry.example.com/svc06:1.6" }
        svc07 = { replicas = 2, cpu = 1024, image = "registry.example.com/svc07:1.7" }
        svc08 = { replicas = 3, cpu = 256, image = "registry.example.com/svc08:1.8" }
        svc09 = { replicas = 1, cpu = 512, image = "registry.example.com/svc09:1.9" }
        svc10 = { replicas = 2, cpu = 768, image = "registry.example.com/svc10:1.10" }
        svc11 = { replicas = 3, cpu = 1024, image = "registry.example.com/svc11:1.11" }
        svc12 = { replicas = 1, cpu = 256, image = "registry.example.com/svc12:1.12" }
        svc13 = { replicas = 2, cpu = 512, image = "registry.example.com/svc13:1.13" }
        svc14 = { replicas = 3, cpu = 768, image = "registry.example.com/svc14:1.14" }
        svc15 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc15:1.15" }
        svc16 = { replicas = 2, cpu = 256, image = "registry.example.com/svc16:1.16" }
        svc17 = { replicas = 3, cpu = 512, image = "registry.example.com/svc17:1.17" }
        svc18 = { replicas = 1, cpu = 768, image = "registry.example.com/svc18:1.18" }
        svc19 = { replicas = 2, cpu = 1024, image = "registry.example.com/svc19:1.19" }
        svc20 = { replicas = 3, cpu = 256, image = "registry.example.com/svc20:1.20" }
        svc21 = { replicas = 1, cpu = 512, image = "registry.example.com/svc21:1.21" }
        svc22 = { replicas = 2, cpu = 768, image = "registry.example.com/svc22:1.22" }
        svc23 = { replicas = 3, cpu = 1024, image = "registry.example.com/svc23:1.23" }
        svc24 = { replicas = 1, cpu = 256, image = "registry.example.com/svc24:1.24" }
        svc25 = { replicas = 2, cpu = 512, image = "registry.example.com/svc25:1.25" }
        svc26 = { replicas = 3, cpu = 768, image = "registry.example.com/svc26:1.26" }
        svc27 = { replicas = 1, cpu = 1024, image = "registry.example.com/svc27:1.27" }
        svc28 = { replicas = 2, cpu = 256, image = "registry.example.com/svc28:1.28" }
        svc29 = { replicas = 3, cpu = 512, image = "registry.example.com/svc29:1.29" }
      }
    }
  }
  deployments = flatten([
    for env, e in local.envs : [
      for name, s in e.services : {
        key      = "${env}-${name}"
        env      = env
        name     = name
        replicas = s.replicas
        cpu      = s.cpu
        image    = s.image
      }
    ]
  ])
  by_key = { for d in local.deployments : d.key => d }
  summary = {
    for k in keys(local.by_key) : k => "${local.by_key[k].env}/${local.by_key[k].name}:${local.by_key[k].cpu}"
  }
}

resource "aws_ecs_service" "this" {
  for_each      = local.by_key
  name          = each.key
  desired_count = each.value.replicas
  tags = {
    for k, v in { env = each.value.env, service = each.value.name, image = each.value.image } : k => v
  }
}

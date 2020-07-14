//
// Created by Juan Pablo Melgarejo on 7/14/20.
//

#include "engine.hpp"

Engine::Engine()
{
    blocks = {16777216, 4194304, 1048576, 262144, 65536, 16384, 4096, 1024, 256, 64, 16, 4, 1 };

    devices = { 1, 40};
    device_names = {"ssd", "hdd"};

    cipher_names = {"botan-CAMELLIA-128-XTS", "botan-CAMELLIA-192-XTS", "botan-CAMELLIA-256-XTS", "cryptopp-AES-128-CBC", "cryptopp-AES-128-CBC", "cryptopp-AES-128-CFB", "cryptopp-AES-128-CFB", "cryptopp-AES-128-CTR", "cryptopp-AES-128-CTR", "cryptopp-AES-128-ECB", "cryptopp-AES-128-OFB", "cryptopp-AES-192-CBC", "cryptopp-AES-192-CBC", "cryptopp-AES-192-CBC", "cryptopp-AES-192-CFB", "cryptopp-AES-192-CFB", "cryptopp-AES-192-CTR", "cryptopp-AES-192-CTR", "cryptopp-AES-192-CTR", "cryptopp-AES-192-ECB", "cryptopp-AES-256-CBC", "cryptopp-AES-256-CBC", "cryptopp-AES-256-CFB", "cryptopp-AES-256-CTR", "cryptopp-AES-256-CTR", "cryptopp-AES-256-CTR", "cryptopp-AES-256-ECB", "cryptopp-AES-256-ECB", "cryptopp-AES-256-OFB", "cryptopp-ARIA-128-CBC", "cryptopp-ARIA-128-CBC", "cryptopp-ARIA-128-CBC", "cryptopp-ARIA-128-CFB", "cryptopp-ARIA-128-CFB", "cryptopp-ARIA-128-CFB", "cryptopp-ARIA-128-CTR", "cryptopp-ARIA-128-CTR", "cryptopp-ARIA-128-CTR", "cryptopp-ARIA-128-ECB", "cryptopp-ARIA-128-OFB", "cryptopp-ARIA-128-OFB", "cryptopp-ARIA-128-OFB", "cryptopp-ARIA-192-CFB", "cryptopp-ARIA-192-CFB", "cryptopp-ARIA-192-CFB", "cryptopp-ARIA-192-CTR", "cryptopp-ARIA-192-CTR", "cryptopp-ARIA-192-CTR", "cryptopp-ARIA-192-OFB", "cryptopp-ARIA-192-OFB", "cryptopp-ARIA-192-OFB", "cryptopp-ARIA-256-CFB", "cryptopp-ARIA-256-CFB", "cryptopp-ARIA-256-CFB", "cryptopp-ARIA-256-CFB", "cryptopp-ARIA-256-CTR", "cryptopp-ARIA-256-CTR", "cryptopp-ARIA-256-CTR", "cryptopp-ARIA-256-CTR", "cryptopp-ARIA-256-ECB", "cryptopp-ARIA-256-OFB", "cryptopp-ARIA-256-OFB", "cryptopp-ARIA-256-OFB", "cryptopp-ARIA-256-OFB", "cryptopp-CAMELLIA-128-CBC", "cryptopp-CAMELLIA-128-CBC", "cryptopp-CAMELLIA-128-CBC", "cryptopp-CAMELLIA-192-OFB", "cryptopp-CAMELLIA-256-CBC", "cryptopp-CAMELLIA-256-CBC", "cryptopp-CAMELLIA-256-CBC", "cryptopp-CAMELLIA-256-CBC", "gcrypt-AES-128-CFB", "gcrypt-AES-128-CFB", "gcrypt-AES-128-CTR", "gcrypt-AES-128-CTR", "gcrypt-AES-192-CFB", "gcrypt-AES-192-CFB", "gcrypt-AES-192-CFB", "gcrypt-AES-192-CTR", "gcrypt-AES-192-CTR", "gcrypt-AES-192-CTR", "gcrypt-AES-256-CFB", "gcrypt-AES-256-CTR", "gcrypt-AES-256-CTR", "gcrypt-AES-256-CTR", "gcrypt-CAMELLIA-128-CTR", "gcrypt-CAMELLIA-192-CFB", "gcrypt-CAMELLIA-192-CTR", "gcrypt-CAMELLIA-192-CTR", "gcrypt-CAMELLIA-256-CFB", "gcrypt-CAMELLIA-256-CTR", "gcrypt-CAMELLIA-256-CTR", "openssl-AES-128-CBC", "openssl-AES-128-CBC", "openssl-AES-128-CFB", "openssl-AES-128-CFB", "openssl-AES-128-CTR", "openssl-AES-128-CTR", "openssl-AES-128-ECB", "openssl-AES-128-OFB", "openssl-AES-128-OFB", "openssl-AES-128-XTS", "openssl-AES-128-XTS", "openssl-AES-128-XTS", "openssl-AES-128-XTS", "openssl-AES-192-CBC", "openssl-AES-192-CBC", "openssl-AES-192-CBC", "openssl-AES-192-CFB", "openssl-AES-192-CFB", "openssl-AES-192-CFB", "openssl-AES-192-CTR", "openssl-AES-192-CTR", "openssl-AES-192-CTR", "openssl-AES-192-ECB", "openssl-AES-192-OFB", "openssl-AES-192-OFB", "openssl-AES-192-OFB", "openssl-AES-256-CBC", "openssl-AES-256-CBC", "openssl-AES-256-CBC", "openssl-AES-256-CFB", "openssl-AES-256-CFB", "openssl-AES-256-CFB", "openssl-AES-256-CTR", "openssl-AES-256-CTR", "openssl-AES-256-CTR", "openssl-AES-256-ECB", "openssl-AES-256-ECB", "openssl-AES-256-OFB", "openssl-AES-256-OFB", "openssl-AES-256-OFB", "openssl-AES-256-XTS", "openssl-AES-256-XTS", "openssl-AES-256-XTS", "openssl-AES-256-XTS", "openssl-ARIA-128-CBC", "openssl-ARIA-128-CBC", "openssl-ARIA-128-CBC", "openssl-ARIA-128-CFB", "openssl-ARIA-128-CFB", "openssl-ARIA-128-CFB", "openssl-ARIA-192-CBC", "openssl-ARIA-192-CBC", "openssl-ARIA-192-CFB", "openssl-ARIA-192-CFB", "openssl-ARIA-192-CFB", "openssl-ARIA-192-CTR", "openssl-ARIA-192-ECB", "openssl-ARIA-192-ECB", "openssl-ARIA-192-OFB", "openssl-ARIA-192-OFB", "openssl-ARIA-256-CBC", "openssl-ARIA-256-CBC", "openssl-ARIA-256-CBC", "openssl-ARIA-256-CBC", "openssl-ARIA-256-CFB", "openssl-ARIA-256-CFB", "openssl-ARIA-256-CFB", "openssl-ARIA-256-CFB", "openssl-ARIA-256-ECB", "openssl-ARIA-256-ECB", "openssl-ARIA-256-OFB", "openssl-ARIA-256-OFB", "openssl-ARIA-256-OFB", "openssl-SEED-128-CBC", "openssl-SEED-128-CBC", "openssl-SEED-128-CFB", "wolfcrypt-AES-128-CTR", "wolfcrypt-AES-128-CTR", "wolfcrypt-AES-192-CTR", "wolfcrypt-AES-192-CTR", "wolfcrypt-AES-192-CTR", "wolfcrypt-AES-256-CTR", "wolfcrypt-AES-256-CTR", "wolfcrypt-AES-256-CTR" };

    sec_levels = {5, 5, 5, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 3, 2, 3, 1, 2, 3, 1, 2, 3, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 4, 1, 2, 3, 4, 2, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 1, 2, 1, 2, 3, 1, 2, 3, 3, 1, 2, 3, 3, 4, 3, 4, 4, 3, 4, 1, 2, 1, 2, 1, 2, 1, 1, 2, 1, 2, 3, 4, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 1, 2, 3, 1, 2, 3, 4, 1, 2, 3, 1, 2, 3, 1, 2, 1, 2, 3, 2, 1, 2, 2, 3, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 1, 2, 3, 2, 3, 2, 1, 2, 1, 2, 3, 1, 2, 3 };


    processors =
            {
                    {59731560, 0, 66307013, 0, 179713816, 0, 0, 7339902994, 30071257812, 115799963541, 470967416666, 0, 0 },
                    {0, 65436749, 0, 0, 0, 512270141, 1829022867, 0, 0, 0, 0, 0, 0 },
                    {0, 0, 0, 96325098, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {2956596, 3779835, 6769572, 18454058, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {2956596, 3779835, 6769572, 18454058, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {3150268, 3892226, 6479958, 17064530, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {3150268, 3892226, 6479958, 17064530, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {1609633, 2296586, 5238079, 15904747, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {1609633, 2296586, 5238079, 15904747, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {1679524, 2667174, 5204563, 16644607, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {0, 5055578, 8028706, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {3527481, 4238752, 7833007, 22061453, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {3527481, 4238752, 7833007, 22061453, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {3527481, 4238752, 7833007, 22061453, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {4618006, 5888680, 7982666, 20222979, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {4618006, 5888680, 7982666, 20222979, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {1756688, 2686742, 5906565, 19420494, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {1756688, 2686742, 5906565, 19420494, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {1756688, 2686742, 5906565, 19420494, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {1977176, 2649503, 6245292, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {3730304, 4755755, 8105266, 20947615, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {3730304, 4755755, 8105266, 20947615, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {4450674, 5852035, 8467947, 21640946, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {1953337, 2806043, 6433140, 19785268, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {1953337, 2806043, 6433140, 19785268, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {1953337, 2806043, 6433140, 19785268, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {1844867, 2791864, 5944371, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {1844867, 2791864, 5944371, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {0, 0, 0, 22843227, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {0, 0, 0, 0, 0, 0, 0, 2461068033, 0, 0, 0, 623595166666, 0 },
                    {0, 0, 0, 0, 0, 0, 0, 2461068033, 0, 0, 0, 623595166666, 0 },
                    {0, 0, 0, 0, 0, 0, 0, 2461068033, 0, 0, 0, 623595166666, 0 },
                    {0, 0, 0, 0, 0, 171626302, 586254069, 2338342773, 9285014322, 37044380208, 148829625000, 592742833333, 2340359333333 },
                    {0, 0, 0, 0, 0, 171626302, 586254069, 2338342773, 9285014322, 37044380208, 148829625000, 592742833333, 2340359333333 },
                    {0, 0, 0, 0, 0, 171626302, 586254069, 2338342773, 9285014322, 37044380208, 148829625000, 592742833333, 2340359333333 },
                    {0, 0, 0, 0, 53820348, 176768147, 612327311, 2312021484, 9147204427, 35805661458, 143295770833, 590094083333, 2373356333333 },
                    {0, 0, 0, 0, 53820348, 176768147, 612327311, 2312021484, 9147204427, 35805661458, 143295770833, 590094083333, 2373356333333 },
                    {0, 0, 0, 0, 53820348, 176768147, 612327311, 2312021484, 9147204427, 35805661458, 143295770833, 590094083333, 2373356333333 },
                    {0, 0, 0, 0, 0, 0, 0, 0, 9206423177, 36909083333, 153947312500, 603596583333, 2485250000000 },
                    {0, 0, 0, 0, 55652893, 178974772, 587487792, 2226976888, 9103044270, 35395390625, 146189416666, 586080916666, 2404719333333 },
                    {0, 0, 0, 0, 55652893, 178974772, 587487792, 2226976888, 9103044270, 35395390625, 146189416666, 586080916666, 2404719333333 },
                    {0, 0, 0, 0, 55652893, 178974772, 587487792, 2226976888, 9103044270, 35395390625, 146189416666, 586080916666, 2404719333333 },
                    {0, 0, 0, 0, 59216842, 171670979, 590669270, 2283576171, 8911873697, 36339171875, 144182000000, 580150916666, 0 },
                    {0, 0, 0, 0, 59216842, 171670979, 590669270, 2283576171, 8911873697, 36339171875, 144182000000, 580150916666, 0 },
                    {0, 0, 0, 0, 59216842, 171670979, 590669270, 2283576171, 8911873697, 36339171875, 144182000000, 580150916666, 0 },
                    {0, 0, 0, 0, 57522893, 179449218, 599193522, 2189237955, 9127115885, 35461088541, 142210187500, 590653250000, 2293082666666 },
                    {0, 0, 0, 0, 57522893, 179449218, 599193522, 2189237955, 9127115885, 35461088541, 142210187500, 590653250000, 2293082666666 },
                    {0, 0, 0, 0, 57522893, 179449218, 599193522, 2189237955, 9127115885, 35461088541, 142210187500, 590653250000, 2293082666666 },
                    {0, 0, 0, 0, 0, 171084940, 584506998, 2303465169, 9022105468, 34881968750, 138255750000, 569246750000, 2345911333333 },
                    {0, 0, 0, 0, 0, 171084940, 584506998, 2303465169, 9022105468, 34881968750, 138255750000, 569246750000, 2345911333333 },
                    {0, 0, 0, 0, 0, 171084940, 584506998, 2303465169, 9022105468, 34881968750, 138255750000, 569246750000, 2345911333333 },
                    {0, 0, 0, 32188275, 0, 172667277, 604588460, 2249983072, 8844135416, 37265359375, 144671187500, 592356750000, 2248630333333 },
                    {0, 0, 0, 32188275, 0, 172667277, 604588460, 2249983072, 8844135416, 37265359375, 144671187500, 592356750000, 2248630333333 },
                    {0, 0, 0, 32188275, 0, 172667277, 604588460, 2249983072, 8844135416, 37265359375, 144671187500, 592356750000, 2248630333333 },
                    {0, 0, 0, 32188275, 0, 172667277, 604588460, 2249983072, 8844135416, 37265359375, 144671187500, 592356750000, 2248630333333 },
                    {0, 0, 0, 0, 61722223, 169587585, 599900227, 2317113932, 9082106770, 35506041666, 141955708333, 583403833333, 2232288666666 },
                    {0, 0, 0, 0, 61722223, 169587585, 599900227, 2317113932, 9082106770, 35506041666, 141955708333, 583403833333, 2232288666666 },
                    {0, 0, 0, 0, 61722223, 169587585, 599900227, 2317113932, 9082106770, 35506041666, 141955708333, 583403833333, 2232288666666 },
                    {0, 0, 0, 0, 61722223, 169587585, 599900227, 2317113932, 9082106770, 35506041666, 141955708333, 583403833333, 2232288666666 },
                    {0, 0, 0, 0, 0, 0, 0, 0, 9795360677, 0, 0, 0, 0 },
                    {0, 0, 0, 0, 0, 0, 598551269, 2205699544, 9056214843, 36248713541, 142304291666, 571443666666, 2196793666666 },
                    {0, 0, 0, 0, 0, 0, 598551269, 2205699544, 9056214843, 36248713541, 142304291666, 571443666666, 2196793666666 },
                    {0, 0, 0, 0, 0, 0, 598551269, 2205699544, 9056214843, 36248713541, 142304291666, 571443666666, 2196793666666 },
                    {0, 0, 0, 0, 0, 0, 598551269, 2205699544, 9056214843, 36248713541, 142304291666, 571443666666, 2196793666666 },
                    {0, 0, 0, 0, 59341735, 0, 645124186, 0, 0, 38458625000, 152182416666, 0, 2472843666666 },
                    {0, 0, 0, 0, 59341735, 0, 645124186, 0, 0, 38458625000, 152182416666, 0, 2472843666666 },
                    {0, 0, 0, 0, 59341735, 0, 645124186, 0, 0, 38458625000, 152182416666, 0, 2472843666666 },
                    {0, 0, 0, 31384869, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {0, 0, 0, 31921424, 63024805, 180576822, 0, 2420232747, 0, 0, 155492187500, 0, 0 },
                    {0, 0, 0, 31921424, 63024805, 180576822, 0, 2420232747, 0, 0, 155492187500, 0, 0 },
                    {0, 0, 0, 31921424, 63024805, 180576822, 0, 2420232747, 0, 0, 155492187500, 0, 0 },
                    {0, 0, 0, 31921424, 63024805, 180576822, 0, 2420232747, 0, 0, 155492187500, 0, 0 },
                    {3162744, 5015560, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {3162744, 5015560, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {1907627, 3620432, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {1907627, 3620432, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {3485006, 5226690, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {3485006, 5226690, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {3485006, 5226690, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {2063934, 3838057, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {2063934, 3838057, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {2063934, 3838057, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {3864605, 5350601, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {2139195, 3739352, 10413178, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {2139195, 3739352, 10413178, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {2139195, 3739352, 10413178, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {4046003, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {12338333, 0, 21604854, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {4829871, 6742645, 13995808, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {4829871, 6742645, 13995808, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {0, 14198517, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {4969530, 6617652, 14294028, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {4969530, 6617652, 14294028, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {2698915, 3284628, 5332104, 12796712, 41390655, 163721964, 613864501, 0, 0, 0, 0, 0, 2492034000000 },
                    {2698915, 3284628, 5332104, 12796712, 41390655, 163721964, 613864501, 0, 0, 0, 0, 0, 2492034000000 },
                    {0, 0, 0, 14959545, 47660471, 159400329, 611127848, 0, 0, 0, 0, 0, 2499171666666 },
                    {0, 0, 0, 14959545, 47660471, 159400329, 611127848, 0, 0, 0, 0, 0, 2499171666666 },
                    {1442652, 2064775, 4257390, 12644320, 46025487, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {1442652, 2064775, 4257390, 12644320, 46025487, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {1450764, 1990916, 3877563, 11384188, 40016983, 158587422, 624293619, 0, 0, 38001614583, 0, 0, 0 },
                    {0, 0, 7058483, 16457644, 50554168, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {0, 0, 7058483, 16457644, 50554168, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {1503233, 1914846, 3575506, 10010742, 34496266, 130989034, 504592285, 2038791666, 8013419270, 31929463541, 130858854166, 0, 0 },
                    {1503233, 1914846, 3575506, 10010742, 34496266, 130989034, 504592285, 2038791666, 8013419270, 31929463541, 130858854166, 0, 0 },
                    {1503233, 1914846, 3575506, 10010742, 34496266, 130989034, 504592285, 2038791666, 8013419270, 31929463541, 130858854166, 0, 0 },
                    {1503233, 1914846, 3575506, 10010742, 34496266, 130989034, 504592285, 2038791666, 8013419270, 31929463541, 130858854166, 0, 0 },
                    {3007328, 3450348, 5401224, 13991537, 44613927, 155444274, 606080159, 2433742838, 9416535156, 37560223958, 0, 615004333333, 2431504000000 },
                    {3007328, 3450348, 5401224, 13991537, 44613927, 155444274, 606080159, 2433742838, 9416535156, 37560223958, 0, 615004333333, 2431504000000 },
                    {3007328, 3450348, 5401224, 13991537, 44613927, 155444274, 606080159, 2433742838, 9416535156, 37560223958, 0, 615004333333, 2431504000000 },
                    {0, 6356755, 9296806, 15314806, 46030807, 160323791, 587285563, 2422128906, 9620065104, 37491109375, 148689104166, 623847416666, 2351602333333 },
                    {0, 6356755, 9296806, 15314806, 46030807, 160323791, 587285563, 2422128906, 9620065104, 37491109375, 148689104166, 623847416666, 2351602333333 },
                    {0, 6356755, 9296806, 15314806, 46030807, 160323791, 587285563, 2422128906, 9620065104, 37491109375, 148689104166, 623847416666, 2351602333333 },
                    {1526331, 2001677, 4381453, 13656906, 43546656, 179048116, 0, 0, 0, 0, 0, 0, 0 },
                    {1526331, 2001677, 4381453, 13656906, 43546656, 179048116, 0, 0, 0, 0, 0, 0, 0 },
                    {1526331, 2001677, 4381453, 13656906, 43546656, 179048116, 0, 0, 0, 0, 0, 0, 0 },
                    {1545353, 2072872, 3825222, 11260403, 39951314, 156091105, 574796549, 2348733398, 9654000000, 38299395833, 151379458333, 621706250000, 2399210666666 },
                    {0, 5431002, 8036716, 17667816, 57201777, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {0, 5431002, 8036716, 17667816, 57201777, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {0, 5431002, 8036716, 17667816, 57201777, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {3562047, 4148392, 5953116, 13544932, 43597747, 154508422, 596401123, 2379964843, 9427402343, 38020822916, 151398562500, 595844583333, 2447593000000 },
                    {3562047, 4148392, 5953116, 13544932, 43597747, 154508422, 596401123, 2379964843, 9427402343, 38020822916, 151398562500, 595844583333, 2447593000000 },
                    {3562047, 4148392, 5953116, 13544932, 43597747, 154508422, 596401123, 2379964843, 9427402343, 38020822916, 151398562500, 595844583333, 2447593000000 },
                    {0, 0, 8786728, 16692353, 51100199, 166747802, 594397542, 2417814453, 9646207031, 38298916666, 148559604166, 598061250000, 2502513333333 },
                    {0, 0, 8786728, 16692353, 51100199, 166747802, 594397542, 2417814453, 9646207031, 38298916666, 148559604166, 598061250000, 2502513333333 },
                    {0, 0, 8786728, 16692353, 51100199, 166747802, 594397542, 2417814453, 9646207031, 38298916666, 148559604166, 598061250000, 2502513333333 },
                    {1815380, 2247976, 4437295, 13110759, 46398468, 178331949, 0, 0, 0, 0, 0, 0, 0 },
                    {1815380, 2247976, 4437295, 13110759, 46398468, 178331949, 0, 0, 0, 0, 0, 0, 0 },
                    {1815380, 2247976, 4437295, 13110759, 46398468, 178331949, 0, 0, 0, 0, 0, 0, 0 },
                    {1596154, 2009076, 4088867, 11524486, 40618835, 0, 608670247, 2456772786, 0, 0, 0, 602577083333, 2423898666666 },
                    {1596154, 2009076, 4088867, 11524486, 40618835, 0, 608670247, 2456772786, 0, 0, 0, 602577083333, 2423898666666 },
                    {0, 6265663, 9090189, 18254603, 54948028, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {0, 6265663, 9090189, 18254603, 54948028, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {0, 6265663, 9090189, 18254603, 54948028, 0, 0, 0, 0, 0, 0, 0, 0 },
                    {1655172, 2319075, 3875182, 10544682, 34805547, 130754089, 508409830, 2029726236, 8288533854, 32891526041, 132475791666, 0, 0 },
                    {1655172, 2319075, 3875182, 10544682, 34805547, 130754089, 508409830, 2029726236, 8288533854, 32891526041, 132475791666, 0, 0 },
                    {1655172, 2319075, 3875182, 10544682, 34805547, 130754089, 508409830, 2029726236, 8288533854, 32891526041, 132475791666, 0, 0 },
                    {1655172, 2319075, 3875182, 10544682, 34805547, 130754089, 508409830, 2029726236, 8288533854, 32891526041, 132475791666, 0, 0 },
                    {0, 0, 0, 0, 60166320, 0, 0, 0, 9786554687, 0, 0, 0, 0 },
                    {0, 0, 0, 0, 60166320, 0, 0, 0, 9786554687, 0, 0, 0, 0 },
                    {0, 0, 0, 0, 60166320, 0, 0, 0, 9786554687, 0, 0, 0, 0 },
                    {0, 0, 0, 0, 58937357, 175237060, 0, 0, 0, 0, 0, 0, 2422190000000 },
                    {0, 0, 0, 0, 58937357, 175237060, 0, 0, 0, 0, 0, 0, 2422190000000 },
                    {0, 0, 0, 0, 58937357, 175237060, 0, 0, 0, 0, 0, 0, 2422190000000 },
                    {0, 0, 0, 0, 0, 0, 0, 0, 9786790364, 0, 0, 0, 0 },
                    {0, 0, 0, 0, 0, 0, 0, 0, 9786790364, 0, 0, 0, 0 },
                    {0, 0, 0, 0, 0, 0, 0, 0, 0, 38486812500, 0, 618127750000, 0 },
                    {0, 0, 0, 0, 0, 0, 0, 0, 0, 38486812500, 0, 618127750000, 0 },
                    {0, 0, 0, 0, 0, 0, 0, 0, 0, 38486812500, 0, 618127750000, 0 },
                    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 155913541666, 0, 0 },
                    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 624211750000, 0 },
                    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 624211750000, 0 },
                    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 625871666666, 0 },
                    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 625871666666, 0 },
                    {0, 0, 0, 0, 61032236, 0, 0, 0, 0, 0, 151710416666, 0, 2440834333333 },
                    {0, 0, 0, 0, 61032236, 0, 0, 0, 0, 0, 151710416666, 0, 2440834333333 },
                    {0, 0, 0, 0, 61032236, 0, 0, 0, 0, 0, 151710416666, 0, 2440834333333 },
                    {0, 0, 0, 0, 61032236, 0, 0, 0, 0, 0, 151710416666, 0, 2440834333333 },
                    {0, 0, 0, 0, 0, 0, 0, 0, 9746416666, 0, 0, 635652500000, 2475329666666 },
                    {0, 0, 0, 0, 0, 0, 0, 0, 9746416666, 0, 0, 635652500000, 2475329666666 },
                    {0, 0, 0, 0, 0, 0, 0, 0, 9746416666, 0, 0, 635652500000, 2475329666666 },
                    {0, 0, 0, 0, 0, 0, 0, 0, 9746416666, 0, 0, 635652500000, 2475329666666 },
                    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 155784375000, 0, 0 },
                    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 155784375000, 0, 0 },
                    {0, 0, 0, 0, 0, 0, 0, 2390324544, 0, 0, 0, 0, 0 },
                    {0, 0, 0, 0, 0, 0, 0, 2390324544, 0, 0, 0, 0, 0 },
                    {0, 0, 0, 0, 0, 0, 0, 2390324544, 0, 0, 0, 0, 0 },
                    {0, 0, 0, 0, 0, 0, 630934895, 0, 0, 38879906250, 0, 0, 0 },
                    {0, 0, 0, 0, 0, 0, 630934895, 0, 0, 38879906250, 0, 0, 0 },
                    {0, 0, 0, 0, 0, 0, 0, 0, 0, 38581239583, 0, 0, 0 },
                    {0, 0, 6812103, 11955268, 27481135, 81803588, 279479329, 1144950195, 4637617187, 18271401041, 71885000000, 296696916666, 1183328666666 },
                    {0, 0, 6812103, 11955268, 27481135, 81803588, 279479329, 1144950195, 4637617187, 18271401041, 71885000000, 296696916666, 1183328666666 },
                    {0, 0, 7744788, 10610158, 27298934, 87245300, 298894449, 1167553059, 4634687500, 17934536458, 74744854166, 291940416666, 1156343666666 },
                    {0, 0, 7744788, 10610158, 27298934, 87245300, 298894449, 1167553059, 4634687500, 17934536458, 74744854166, 291940416666, 1156343666666 },
                    {0, 0, 7744788, 10610158, 27298934, 87245300, 298894449, 1167553059, 4634687500, 17934536458, 74744854166, 291940416666, 1156343666666 },
                    {0, 0, 8318701, 12434319, 30268315, 83885152, 297151855, 1187051106, 4409654947, 18541651041, 71026000000, 288405083333, 1136255666666 },
                    {0, 0, 8318701, 12434319, 30268315, 83885152, 297151855, 1187051106, 4409654947, 18541651041, 71026000000, 288405083333, 1136255666666 },
                    {0, 0, 8318701, 12434319, 30268315, 83885152, 297151855, 1187051106, 4409654947, 18541651041, 71026000000, 288405083333, 1136255666666 }
            };
}

std::vector<std::vector<std::string>> Engine::minimizeTime(int64_t file_size, int sec_level)
{
    using namespace operations_research;

    // TODO: performance of INF horizon
    int64_t horizon = INT64_MAX - 1;

    struct Task {
        sat::IntervalVar p_interval;
        sat::IntervalVar io_interval;
        int64_t block_len;
    };

    std::vector<sat::IntervalVar> all_p_intervals;
    std::vector<sat::IntVar> all_io_ends;

    std::vector<std::vector<sat::IntervalVar>> per_device_intervals(devices.size());

    std::vector<std::vector<std::vector<Task>>> all_tasks(processors.size());
    long task_count = 0;

    std::vector<sat::BoolVar> all_chosen;
    std::vector<int64_t> all_block_sizes;
    std::vector<int64_t> all_sec_levels;

    sat::CpModelBuilder cp_model;
    Domain domain(0, horizon);
    for (int proc_id = 0; proc_id < processors.size(); proc_id++)
    {
        if (sec_levels[proc_id] != sec_level)
            continue;

        all_tasks[proc_id] = std::vector<std::vector<Task>>(blocks.size());
        for (int block_id = 0; block_id < blocks.size(); block_id++)
        {
            if (processors[proc_id][block_id] == 0 || blocks[block_id] > file_size)
                continue;
            all_tasks[proc_id][block_id] = std::vector<Task>(devices.size());
            for (int device_id = 0; device_id < devices.size(); device_id++)
            {
                std::stringstream ss;
                ss << "_" << block_id << "_" << proc_id << "_" << device_id;
                sat::BoolVar chosen = cp_model.NewBoolVar().WithName("chosen" + ss.str());
                all_chosen.push_back(chosen);
                all_block_sizes.push_back(blocks[block_id]);
                all_sec_levels.push_back(sec_levels[proc_id]);

                sat::IntVar p_time = cp_model.NewConstant(blocks[block_id] * processors[proc_id][block_id]);
                sat::IntVar p_start = cp_model.NewIntVar(domain).WithName("p_start" + ss.str());
                sat::IntVar p_end = cp_model.NewIntVar(domain).WithName("p_end" + ss.str());
                sat::IntervalVar p_interval = cp_model.NewOptionalIntervalVar(p_start, p_time, p_end, chosen).WithName("p_interval" + ss.str());

                all_p_intervals.push_back(p_interval);

                sat::IntVar io_time = cp_model.NewConstant(blocks[block_id] * devices[device_id]);
                sat::IntVar io_start = cp_model.NewIntVar(domain).WithName("io_start" + ss.str());
                sat::IntVar io_end = cp_model.NewIntVar(domain).WithName("io_end" + ss.str());
                sat::IntervalVar io_interval = cp_model.NewOptionalIntervalVar(io_start, io_time, io_end, chosen).WithName("io_interval" + ss.str());

                all_io_ends.push_back(io_end);
                per_device_intervals[device_id].push_back(io_interval);

                all_tasks[proc_id][block_id][device_id] = Task{p_interval, io_interval, blocks[block_id]};
                task_count++;

                /// Precedence constraint
                cp_model.AddGreaterOrEqual(io_start, p_end).OnlyEnforceIf(chosen);
            }
        }
    }

    std::cout << "Finished preparing data" << std::endl;
    std::cout << "\tConsidering " << task_count << " tasks" << std::endl;

    /// Constraints
    cp_model.AddNoOverlap(all_p_intervals);
    for (int device_id = 0; device_id < devices.size(); device_id++)
    {
        cp_model.AddNoOverlap(per_device_intervals[device_id]);
    }

    cp_model.AddEquality(sat::LinearExpr::BooleanScalProd(all_chosen, all_block_sizes), file_size);

    // Just for evaluation purposes
    sat::IntVar overall_security = cp_model.NewIntVar(domain).WithName("overall_security");
    cp_model.AddEquality(sat::LinearExpr::BooleanScalProd(all_chosen, all_sec_levels), overall_security);

    /// Objective
    sat::IntVar obj_var = cp_model.NewIntVar(domain).WithName("makespan");
    cp_model.AddMaxEquality(obj_var, all_io_ends);
    cp_model.Minimize(obj_var);

    sat::IntVar choices = cp_model.NewIntVar({0, task_count}).WithName("choices");
    cp_model.AddEquality(choices, sat::LinearExpr::BooleanSum(all_chosen));
    cp_model.Minimize(choices);


    /// Add time limit constraint in order to find feasible solutions
    sat::Model model;
    sat::SatParameters parameters;
    parameters.set_max_time_in_seconds(10.0);
    model.Add(NewSatParameters(parameters));

    /// Solver
    sat::CpModelProto model_proto = cp_model.Build();
    sat::CpSolverResponse response = sat::SolveCpModel(model_proto, &model);
    std::cout << sat::CpSolverResponseStats(response) << std::endl;

    std::vector<std::vector<std::string>> result;
    if (response.status() == sat::CpSolverStatus::OPTIMAL || response.status() == sat::CpSolverStatus::FEASIBLE)
    {
        std::cout << "Schedule Length: " << sat::SolutionIntegerValue(response, obj_var) << "\n";

        auto mean_sec_level = (double) sat::SolutionIntegerValue(response, overall_security) / sat::SolutionIntegerValue(response, choices);
        std::cout << "Average sec. level: " << mean_sec_level << "\n";

        std::stringstream processor_tasks;
        for (int proc_id = 0; proc_id < processors.size(); proc_id++)
        {
            if (sec_levels[proc_id] != sec_level)
                continue;

            for (int device_id = 0; device_id < devices.size(); device_id++)
            {
                std::stringstream chosen_blocks;
                std::stringstream proc_times;
                bool print = false;
                for (int block_id = 0; block_id < blocks.size(); block_id++)
                {
                    if (processors[proc_id][block_id] == 0 || blocks[block_id] > file_size)
                        continue;

                    auto &task = all_tasks[proc_id][block_id][device_id];
                    if (!sat::SolutionBooleanValue(response, task.p_interval.PresenceBoolVar()))
                    {
                        continue;
                    }
                    print = true;
                    // start_p, bytes, encryption, device
                    std::vector<std::string> res_line(4);
                    res_line[0] = std::to_string(sat::SolutionIntegerValue(response, task.p_interval.StartVar()));
                    res_line[1] = std::to_string(task.block_len);
                    res_line[2] = cipher_names[proc_id];
                    res_line[3] = device_names[device_id];
                    result.push_back(res_line);

                    std::string blk_str = "block " + std::to_string(task.block_len) + " B ";
                    chosen_blocks << std::setw(-60) << blk_str;

                    std::stringstream times;
                    times << "p: ["
                          << sat::SolutionIntegerValue(response, task.p_interval.StartVar()) << ", "
                          << sat::SolutionIntegerValue(response, task.p_interval.EndVar()) << "] ";

                    times << "io: ["
                          << sat::SolutionIntegerValue(response, task.io_interval.StartVar()) << ", "
                          << sat::SolutionIntegerValue(response, task.io_interval.EndVar()) << "] ";

                    proc_times <<  std::setw(-60) << times.str();
                }
                if (print)
                {
                    processor_tasks << "Processor " << cipher_names[proc_id] << " by " << device_names[device_id] << " : \n";
                    processor_tasks << chosen_blocks.str() << "\n" << proc_times.str() << "\n\n";
                }
            }
        }


        std::cout << processor_tasks.str() << std::endl;

        std::sort(result.begin(), result.end(),
                [](const std::vector<std::string>& a, const std::vector<std::string>& b) {
                    return a[0] < b[0];
                });

        return result;
    }
}

void Engine::maximizeSecurity(int64_t file_size, int64_t time_available)
{
    using namespace operations_research;

    // TODO: performance of INF horizon
    int64_t horizon = INT64_MAX - 1;

    struct Task {
        sat::IntervalVar p_interval;
        sat::IntervalVar io_interval;
        int64_t block_len;
    };

    std::vector<sat::IntervalVar> all_p_intervals;
    std::vector<sat::IntVar> all_io_ends;

    std::vector<std::vector<sat::IntervalVar>> per_device_intervals(devices.size());

    std::vector<std::vector<std::vector<Task>>> all_tasks(processors.size());
    long task_count = 0;

    std::vector<sat::BoolVar> all_chosen;
    std::vector<int64_t> all_block_sizes;
    std::vector<int64_t> all_sec_levels;
    std::vector<int64_t> all_weighted_sec_levels;

    sat::CpModelBuilder cp_model;
    Domain domain(0, horizon);
    for (int proc_id = 0; proc_id < processors.size(); proc_id++)
    {
        all_tasks[proc_id] = std::vector<std::vector<Task>>(blocks.size());
        for (int block_id = 0; block_id < blocks.size(); block_id++)
        {
            if (processors[proc_id][block_id] == 0 || blocks[block_id] > file_size)
                continue;
            all_tasks[proc_id][block_id] = std::vector<Task>(devices.size());
            for (int device_id = 0; device_id < devices.size(); device_id++)
            {
                std::stringstream ss;
                ss << "_" << block_id << "_" << proc_id << "_" << device_id;
                sat::BoolVar chosen = cp_model.NewBoolVar().WithName("chosen" + ss.str());
                all_chosen.push_back(chosen);
                all_block_sizes.push_back(blocks[block_id]);
                all_sec_levels.push_back(sec_levels[proc_id]);

                // This assumes descending block order
                ulong block_rank = blocks.size() - block_id;
                all_weighted_sec_levels.push_back((int64_t) std::pow(block_rank, sec_levels[proc_id]));

                sat::IntVar p_time = cp_model.NewConstant(blocks[block_id] * processors[proc_id][block_id]);
                sat::IntVar p_start = cp_model.NewIntVar(domain).WithName("p_start" + ss.str());
                sat::IntVar p_end = cp_model.NewIntVar(domain).WithName("p_end" + ss.str());
                sat::IntervalVar p_interval = cp_model.NewOptionalIntervalVar(p_start, p_time, p_end, chosen).WithName("p_interval" + ss.str());

                all_p_intervals.push_back(p_interval);

                sat::IntVar io_time = cp_model.NewConstant(blocks[block_id] * devices[device_id]);
                sat::IntVar io_start = cp_model.NewIntVar(domain).WithName("io_start" + ss.str());
                sat::IntVar io_end = cp_model.NewIntVar(domain).WithName("io_end" + ss.str());
                sat::IntervalVar io_interval = cp_model.NewOptionalIntervalVar(io_start, io_time, io_end, chosen).WithName("io_interval" + ss.str());

                all_io_ends.push_back(io_end);
                per_device_intervals[device_id].push_back(io_interval);

                all_tasks[proc_id][block_id][device_id] = Task{p_interval, io_interval, blocks[block_id]};
                task_count++;

                /// Precedence constraint
                cp_model.AddGreaterOrEqual(io_start, p_end).OnlyEnforceIf(chosen);
            }
        }
    }

    std::cout << "Finished preparing data" << std::endl;
    std::cout << "\tConsidering " << task_count << " tasks" << std::endl;

    /// Constraints
    cp_model.AddNoOverlap(all_p_intervals);
    for (int device_id = 0; device_id < devices.size(); device_id++)
    {
        cp_model.AddNoOverlap(per_device_intervals[device_id]);
    }

    cp_model.AddEquality(sat::LinearExpr::BooleanScalProd(all_chosen, all_block_sizes), file_size);

    sat::IntVar makespan = cp_model.NewIntVar(domain).WithName("makespan");
    cp_model.AddMaxEquality(makespan, all_io_ends);
    cp_model.AddLessOrEqual(makespan, time_available * 1000000);

    // Just for evaluation purposes
    sat::IntVar overall_security = cp_model.NewIntVar(domain).WithName("overall_security");
    cp_model.AddEquality(sat::LinearExpr::BooleanScalProd(all_chosen, all_sec_levels), overall_security);

    /// Objective
    cp_model.Maximize(makespan);

    sat::IntVar weighted_security = cp_model.NewIntVar(domain).WithName("weighted_security");
    cp_model.AddEquality(sat::LinearExpr::BooleanScalProd(all_chosen, all_weighted_sec_levels), weighted_security);
    cp_model.Maximize(weighted_security);

    sat::IntVar choices = cp_model.NewIntVar({0, task_count}).WithName("choices");
    cp_model.AddEquality(choices, sat::LinearExpr::BooleanSum(all_chosen));
    cp_model.Minimize(choices);

    /// Add time limit constraint in order to find feasible solutions
    sat::Model model;
    sat::SatParameters parameters;
    parameters.set_max_time_in_seconds(20.0);
    model.Add(NewSatParameters(parameters));

    /// Solver
    sat::CpModelProto model_proto = cp_model.Build();
    sat::CpSolverResponse response = sat::SolveCpModel(model_proto, &model);
    std::cout << sat::CpSolverResponseStats(response) << std::endl;

    if (response.status() == sat::CpSolverStatus::OPTIMAL || response.status() == sat::CpSolverStatus::FEASIBLE)
    {
        std::cout << "Schedule Length: " << sat::SolutionIntegerValue(response, makespan) << "\n";

        auto mean_sec_level = (double) sat::SolutionIntegerValue(response, overall_security) / sat::SolutionIntegerValue(response, choices);
        std::cout << "Average sec. level: " << mean_sec_level << "\n";

        std::stringstream processor_tasks;
        for (int proc_id = 0; proc_id < processors.size(); proc_id++)
        {
            for (int device_id = 0; device_id < devices.size(); device_id++)
            {
                std::stringstream chosen_blocks;
                std::stringstream proc_times;
                bool print = false;
                for (int block_id = 0; block_id < blocks.size(); block_id++)
                {
                    if (processors[proc_id][block_id] == 0 || blocks[block_id] > file_size)
                        continue;

                    auto &task = all_tasks[proc_id][block_id][device_id];
                    if (!sat::SolutionBooleanValue(response, task.p_interval.PresenceBoolVar()))
                    {
                        continue;
                    }
                    print = true;

                    std::string blk_str = "block " + std::to_string(task.block_len) + " B ";
                    chosen_blocks << std::setw(-60) << blk_str;

                    std::stringstream times;
                    times << "p: ["
                          << sat::SolutionIntegerValue(response, task.p_interval.StartVar()) << ", "
                          << sat::SolutionIntegerValue(response, task.p_interval.EndVar()) << "] ";

                    times << "io: ["
                          << sat::SolutionIntegerValue(response, task.io_interval.StartVar()) << ", "
                          << sat::SolutionIntegerValue(response, task.io_interval.EndVar()) << "] ";

                    proc_times <<  std::setw(-60) << times.str();
                }
                if (print)
                {
                    processor_tasks << "Processor " << cipher_names[proc_id] << " by " << device_names[device_id] << " : \n";
                    processor_tasks << chosen_blocks.str() << "\n" << proc_times.str() << "\n\n";
                }
            }
        }


        std::cout << processor_tasks.str() << std::endl;

        return;
    }
}


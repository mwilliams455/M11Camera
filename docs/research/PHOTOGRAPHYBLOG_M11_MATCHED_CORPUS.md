# Photography Blog Leica M11 Matched DNG/JPEG Corpus

**Source:** https://www.photographyblog.com/reviews/leica_m11_review  
**Reviewed:** 2026-09-08  
**Camera:** Leica M11  
**Lens reported by page:** 50 mm  
**Capture mode:** 60 MP Large JPEG + DNG sample set

## Why this corpus matters

Photography Blog publishes a long sequence of full-size Leica M11 JPEG samples and a corresponding RAW section. The filenames and page exposure metadata align in order:

```text
leica_m11_01.jpg <-> leica_m11_01.dng
leica_m11_02.jpg <-> leica_m11_02.dng
...
```

The page states the JPEG samples are full-sized originals and have not been altered, and separately provides downloadable original DNGs. This makes the set suitable as a matched regression corpus for validating the recovered M11 processing chain.

The direct file pattern observed from the page is:

```text
https://img.photographyblog.com/reviews/leica_m11/sample_images/leica_m11_NN.jpg
https://img.photographyblog.com/reviews/leica_m11/sample_images/leica_m11_NN.dng
```

where `NN` is zero-padded.

## First high-value subset

Do not start by downloading the entire corpus. The following subset spans base ISO, mid ISO and higher ISO while preserving exact RAW/JPEG pairing.

| Pair | Shutter | Aperture | ISO | Why selected |
| --- | ---: | ---: | ---: | --- |
| 01 | 1/200 s | f/4.8 | 125 | first pair; moderate ISO baseline |
| 04 | 1/250 s | f/2 | 64 | base-ISO wide-aperture reference |
| 05 | 1/250 s | f/13 | 1250 | high mid-ISO / small aperture |
| 10 | 1/320 s | f/3.4 | 64 | second base-ISO scene |
| 14 | 1/2000 s | f/2.4 | 64 | bright/high-shutter highlight scene |
| 20 | 1/250 s | f/4.8 | 80 | near-base ISO transition |
| 24 | 1/640 s | f/2 | 64 | base-ISO wide-aperture outdoor scene |
| 31 | 1/200 s | f/9.5 | 125 | lower-ISO closed-aperture scene |
| 34 | 1/250 s | f/5.6 | 640 | medium/high ISO reference |
| 37 | 1/250 s | f/2 | 800 | high-ISO wide-aperture reference |
| 38 | 1/320 s | f/11 | 1600 | highest ISO in the first useful compact subset |
| 45 | 1/320 s | f/4.8 | 100 | low-ISO intermediate state |

## Confirmed page sequence for pairs 01-52

The RAW section repeats the same exposure sequence as the JPEG section, which provides an independent pairing check.

```text
01 ISO125   1/200   f/4.8
02 ISO400   1/250   f/4.8
03 ISO640   1/250   f/6.8
04 ISO64    1/250   f/2
05 ISO1250  1/250   f/13
06 ISO500   1/200   f/8
07 ISO400   1/250   f/9.5
08 ISO200   1/250   f/4.8
09 ISO500   1/250   f/13
10 ISO64    1/320   f/3.4
11 ISO64    1/250   f/6.8
12 ISO400   1/200   f/6.8
13 ISO400   1/250   f/16
14 ISO64    1/2000  f/2.4
15 ISO64    1/250   f/6.8
16 ISO64    1/500   f/2.4
17 ISO64    1/400   f/3.4
18 ISO64    1/1000  f/2
19 ISO64    1/500   f/2
20 ISO80    1/250   f/4.8
21 ISO160   1/200   f/8
22 ISO320   1/250   f/9.5
23 ISO500   1/200   f/13
24 ISO64    1/640   f/2
25 ISO320   1/250   f/11
26 ISO80    1/250   f/2.4
27 ISO160   1/250   f/4.8
28 ISO64    1/640   f/2.8
29 ISO64    1/1600  f/2
30 ISO320   1/200   f/9.5
31 ISO125   1/200   f/9.5
32 ISO64    1/1000  f/3.4
33 ISO64    1/360   f/2.8
34 ISO640   1/250   f/5.6
35 ISO250   1/200   f/9.5
36 ISO64    1/500   f/4
37 ISO800   1/250   f/2
38 ISO1600  1/320   f/11
39 ISO80    1/320   f/6.8
40 ISO64    1/640   f/4
41 ISO250   1/320   f/5.6
42 ISO200   1/320   f/9.5
43 ISO200   1/320   f/8
44 ISO250   1/320   f/6.8
45 ISO100   1/320   f/4.8
46 ISO125   1/360   f/4.8
47 ISO100   1/320   f/16
48 ISO500   1/320   f/8
49 ISO160   1/320   f/9.5
50 ISO160   1/320   f/9.5
51 ISO500   1/320   f/9.5
52 ISO640   1/320   [aperture continues in page RAW list beyond current captured excerpt]
```

## Intended validation use

Once local copies are available, each pair should produce a manifest with at least:

- SHA-256 of DNG and JPEG;
- EXIF shutter / aperture / ISO / lens;
- DNG `AsShotNeutral`;
- `ColorMatrix1/2`;
- `CameraCalibration1/2`;
- calibration illuminants;
- black/white level;
- CFA;
- image dimensions;
- DNG baseline/exposure tags;
- embedded profile/look-table metadata;
- JPEG colour space / ICC profile / dimensions;
- firmware version if retained;
- date/time and any film-style metadata retained in MakerNotes/EXIF.

The first structural test is:

```text
DNG linear sensor samples
-> black/white normalization
-> M11 as-shot white balance
-> candidate CC0
-> candidate tone
-> candidate CC1
-> candidate YCC/gamma/chroma/output
```

and compare against the matching untouched camera JPEG.

## Runtime limitation during initial indexing

The review page and file URLs are reachable from the web browser tool, but this analysis runtime cannot directly stream the large binary DNG/JPEG payloads from `img.photographyblog.com`. Therefore this file records pairing/provenance only; it does not claim that pixel-level or full local ExifTool validation has yet been performed on these files.

The preferred local validation route is to download selected pairs outside this restricted runtime and place them in the project File Library or connected Dropbox, after which they can be analyzed directly.

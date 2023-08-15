# Mifare Forum

Reporting a typo in AN12343 (MIFARE DESFire Light Features and Hints)

https://www.mifare.net/?post_type=topic&p=52230

15.08.2023, awaiting moderation

Dear team,
I found a typo within the named document (Rev. 1.1 — 20 January 2020) on page 44 (7.2.5.1 Example: Bringing the IC into LRP Secure Messaging Mode using SetConfiguration, Table 18. Bringing the IC to LRP Mode by using Cmd.SetConfiguration).

In step 25 the "Data (Cmd Header || Encrypted Data || MAC)" is given as "0541B2BA963075730426D0858D2AA6C4982F579E77FAB49F83" but in step 27 the full command apdu "Cmd.SetConfiguration C-APDU (Cmd || Ins || P1 || P2 || Lc || Data || Le)" is given as "905C00001905[b]00[/b] 41B2BA963075730426D0858D2AA6C4982F579E77FAB49F8300".

Here are the better formatted data as code block:

`Data:             0541B2BA963075730426D0858D2AA6C4982F579E77FAB49F83
C-APDU: 905C000019050041B2BA963075730426D0858D2AA6C4982F579E77FAB49F8300`.

After the configuration option byte "05" is an additional "00" byte that would lead to an error on running the data, without this byte the code runs correctly and brings the PICC in LRP mode (tested).

The correct C-APDU should look like:

`C-APDU: 905C0000190541B2BA963075730426D0858D2AA6C4982F579E77FAB49F8300`

Kind regards
Michael
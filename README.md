# Secure Serial Modbus: Closing the Field-Bus Semantic Gap with Protocol-Native Protection for Serial Modbus RTU/ASCII
## Reference prototype.
Protocols/: is the prototype implementation for the reference management-plane backends. The
three prototype management-plane backends are illustrative instantiations. Just for reference, any deployments related to the application scenario, may define or replace the management-plane credential protocol as long as it authenticates the transcript, derives SAC/content keys with labeled separation, and satisfies the APDU state, replay, fragmentation, and fail-closed invariants. 
1. SSM based on ECC public key certificates is suitable for high-value and high security factories and devices.
2. SSM based on post quantum hybrid signature public key certificate is suitable for future high-value and high security factory equipment environments.
3. SSM based on passwords or pre-shared keys relies on hardware protection. The goal of the protocol is to provide strong security on the basis of low entropy passwords, allowing master-slave devices to negotiate and obtain the same content key while resisting command or key guessing attacks. This type of protocol is suitable for use in factories and equipment with general value and security.
   
## Reference specification.
X.MBSL-sec-v1.1.docx is a draft standard specification for our design.
## Reference docs for ProVerif.
1. ssm_forward_secrecy_proverif.pv
2. ssm_profiles_proverif.pv

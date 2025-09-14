# FMS Lab

## Dependencies
- Docker Compose
- Jupyter Notebook

## Build Instructions
1) From the top level directory: `docker compose up --no-start --build --force-recreate; docker compose up -d notebook; docker compose up -d attacker`
2) Browse to `http://127.0.0.1:8888/tree?token=lab` to interact with the notebook


## Recommended Work Flow
Follow the Jupyter Notebook in order. Run all the python cells to learn about the basic workings of RC4 and the FMS attack. For the offline attack, recovering one byte only, draw the values of all the variables on paper. Keep track of how the S-Box changes and shifts and why weak IVs allow the attack to work. Plug variables into the equations and watch the calculation work. 

## Learning References
Aside from the papers cited in the .bib I used the below resources for inspiration and learning of the FMS attack:
- https://youtu.be/2o3Hs-JDWLs?si=ZHojO6p9YbYVDRgm
- https://github.com/jackieden26/FMS-Attack

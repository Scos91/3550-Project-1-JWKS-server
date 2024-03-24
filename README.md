# 3550-Project-JWKS-server

Project 2 - Deliverables:
1. p2.py - main program
2. testP2.py - test suite for P2
3. gradebot_grade.png - screenshot of gradebot grade for P2
4. test_coverage.png - screenshot of test suite coverage % for P2

How to execute program (in VScode): 
1. Open/run in cmd terminal: 'python p2.py' <- this will start server.
2. Open seperate cmd terminal, run: 'gradebot project2' (must be in same directory as p2.py) <- this will run gradebot against p2.
3. On the seperate cmd terminal (the terminal used to run gradebot), run: 'python -m coverage run -m unittest discover' <- this will run the test suite against p2.py (the P2 server must be running - run 'python p2.py' on first cmd terminal before running this command).
4. On the seperate cmd terminal (the terminal used to run gradebot), run: 'python -m coverage report -m' <- this will produce the % coverage for the test suite (the P2 server must be running - run 'python p2.py' on first cmd terminal before running this command).

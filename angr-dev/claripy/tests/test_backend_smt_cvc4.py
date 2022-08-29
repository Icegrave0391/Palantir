import unittest
import claripy
import nose
from claripy.backends.backend_smtlib_solvers.cvc4_popen import SolverBackendCVC4
import common_backend_smt_solver


class SmtLibSolverTest_CVC4(common_backend_smt_solver.SmtLibSolverTestBase):
    def get_solver(self):
        if 'smtlib_cvc4' not in claripy.backends._backends_by_name:
            raise nose.SkipTest()

        backend = SolverBackendCVC4(daggify=True)
        solver = claripy.SolverStrings(backend=backend, timeout=300000)
        return solver


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(SmtLibSolverTest_CVC4)
    unittest.TextTestRunner(verbosity=2).run(suite)

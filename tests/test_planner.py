import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.agent import AgentState, MethodologyPlanner


class TestMethodologyPlanner(unittest.TestCase):
    def test_web_ports_trigger_web_tools(self):
        state = AgentState(
            target="t",
            ports=[{"port": 80, "state": "open"}],
        )
        planner = MethodologyPlanner()
        plan = planner.suggest(state)
        self.assertIn("httpx", plan["next_steps"])
        self.assertIn("whatweb", plan["next_steps"])
        self.assertIn("nuclei", plan["next_steps"])
        self.assertIn("gobuster", plan["next_steps"])

    def test_ssh_triggers_hydra(self):
        state = AgentState(
            target="t",
            ports=[{"port": 22, "state": "open"}],
        )
        planner = MethodologyPlanner()
        plan = planner.suggest(state)
        self.assertTrue(any("hydra:ssh" == step for step in plan["next_steps"]))

    def test_default_to_full_nmap(self):
        state = AgentState(target="t", ports=[])
        planner = MethodologyPlanner()
        plan = planner.suggest(state)
        self.assertIn("nmap:full", plan["next_steps"])


if __name__ == "__main__":
    unittest.main()

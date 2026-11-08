"""Run the agent scaffold with a local fake model; no API key required."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dorker_agent import Agent


class DemoModel:
    def complete(self, messages):
        task = messages[-1].content
        return f"Received task: {task}\nNext: inspect requirements, implement, test, review."


if __name__ == "__main__":
    agent = Agent(DemoModel(), system_prompt="You are Dorker, a precise coding assistant.")
    print(agent.run("Create unit tests for the registry validator"))

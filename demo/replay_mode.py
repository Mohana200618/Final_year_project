
"""
demo/replay_mode.py
====================
Safe, offline demo replay mode for ThreatScope.

Loads demo scenarios from demo/scenarios.json, runs each through
the full pipeline, and prints a formatted report — no live traffic
or network connections required.

Usage
-----
  python demo/replay_mode.py
  python demo/replay_mode.py --json          # output as JSON
  python demo/replay_mode.py --scenario 3    # run only scenario index 3
"""

import os
import sys
import json
import time
import argparse

# Allow imports from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import feature_schema as fs
from threatscope.pipeline import ThreatScopePipeline


# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------

SEV_ICONS = {
    'Low':      '[LOW     ]',
    'Medium':   '[MEDIUM  ]',
    'High':     '[HIGH    ]',
    'Critical': '[CRITICAL]',
}

STAGE_SHORT = {
    'NORMAL':               'NORMAL',
    'RECONNAISSANCE':       'RECON',
    'INITIAL_ACCESS':       'ACCESS',
    'COMMAND_AND_CONTROL':  'C2',
    'LATERAL_MOVEMENT':     'LATERAL',
    'IMPACT':               'IMPACT',
}


def print_result(r: dict, scenario_name: str, idx: int):
    sev   = r['risk']['severity']
    icon  = SEV_ICONS.get(sev, '[????   ]')
    chain = r['attack_chain']
    stage = STAGE_SHORT.get(chain['current_stage'], chain['current_stage'])
    next_s= STAGE_SHORT.get(chain['next_stage'],    chain['next_stage'])
    mitre = r['mitre']
    tech  = f"{mitre['technique_id']} {mitre['technique_name']}" if mitre['technique_id'] else 'N/A'

    print(f"\n{'='*65}")
    print(f" Scenario {idx+1:02d} : {scenario_name}")
    print(f"{'='*65}")
    print(f"  {icon} Risk Score  : {r['risk']['score']:>3}/100")
    print(f"  Anomalous   : {'YES [!]' if r['is_anomalous'] else 'NO  [ok]'}")
    print(f"  IF Score    : {r['anomaly_score']:.4f}")
    print(f"  Label       : {r['attack_label']} ({r['confidence']*100:.1f}% confidence)")
    print(f"  MITRE Tactic: {mitre['tactic'] or 'N/A'}")
    print(f"  MITRE Tech  : {tech}")
    print(f"  Stage       : {stage}")
    print(f"  Next Stage  : {next_s} ({chain['next_probability']*100:.0f}%)")
    if chain['alt_stage']:
        alt = STAGE_SHORT.get(chain['alt_stage'], chain['alt_stage'])
        print(f"  Alt Stage   : {alt} ({chain['alt_probability']*100:.0f}%)")
    print(f"\n  Recommendations:")
    for a in r['recommendations']:
        prefix = '  !! ' if a.startswith(('URGENT', 'ESCALATE')) else '    - '
        print(f"{prefix}{a}")
    print(f"\n  [Advisory: {r['disclaimer'][:70]}...]")

    # Risk breakdown
    bd = r['risk']['breakdown']
    print(f"\n  Risk Breakdown:")
    for k, v in bd.items():
        bar = '#' * int(v) + '-' * max(0, 35 - int(v))
        print(f"    {k:<30}: {bar} {v:.1f}")


def run_replay(
    scenarios_path: str,
    json_output:    bool = False,
    only_idx:       int  = None,
    delay:          float = 0.0,
) -> list:

    if not os.path.exists(scenarios_path):
        print(f"ERROR: scenarios file not found: {scenarios_path}")
        sys.exit(1)

    with open(scenarios_path) as fh:
        scenarios = json.load(fh)

    print("=" * 65)
    print(" ThreatScope — Demo Replay Mode")
    print("=" * 65)
    print(f" Scenarios     : {len(scenarios)}")
    print(f" Output mode   : {'JSON' if json_output else 'Text'}")
    print(" SAFE MODE: No live traffic. No network connections.")
    print("=" * 65)

    # Load pipeline
    try:
        pipeline = ThreatScopePipeline(require_xgb=False)
    except FileNotFoundError as e:
        print(f"\nERROR: {e}")
        sys.exit(1)

    import pandas as pd

    all_results = []

    for idx, scenario in enumerate(scenarios):
        if only_idx is not None and idx != only_idx:
            continue

        name = scenario.get('name', f'Scenario {idx+1}')
        features = {k: scenario[k] for k in fs.FEATURES}

        df  = pd.DataFrame([features])[fs.FEATURES]
        res = pipeline.run_df(df)[0]
        res['scenario_name'] = name
        res['source_ip']     = scenario.get('source_ip', '?')
        res['dest_ip']       = scenario.get('dest_ip',   '?')
        res['expected_label']= scenario.get('expected_label', 'N/A')

        all_results.append(res)

        if not json_output:
            print_result(res, name, idx)

        if delay > 0:
            time.sleep(delay)

    if json_output:
        print(json.dumps(all_results, indent=2))
    else:
        print(f"\n{'='*65}")
        print(f" REPLAY COMPLETE — {len(all_results)} scenarios processed")
        print(f"{'='*65}")

        # Summary table
        print(f"\n  {'Scenario':<35} {'Label':<32} {'Score':>5} {'Sev':<9}")
        print(f"  {'-'*35} {'-'*32} {'-'*5} {'-'*9}")
        for r in all_results:
            print(f"  {r['scenario_name']:<35} {r['attack_label']:<32} "
                  f"{r['risk']['score']:>5} {r['risk']['severity']:<9}")

    return all_results


# ----------------------------------------------------------------
# CLI entry point
# ----------------------------------------------------------------

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='ThreatScope safe demo replay'
    )
    parser.add_argument(
        '--json', action='store_true',
        help='Output results as JSON instead of formatted text'
    )
    parser.add_argument(
        '--scenario', type=int, default=None,
        help='Run only a specific scenario by index (0-based)'
    )
    parser.add_argument(
        '--delay', type=float, default=0.0,
        help='Seconds to wait between scenarios (default: 0)'
    )
    args = parser.parse_args()

    scenarios_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        'scenarios.json'
    )

    run_replay(
        scenarios_path = scenarios_file,
        json_output    = args.json,
        only_idx       = args.scenario,
        delay          = args.delay,
    )

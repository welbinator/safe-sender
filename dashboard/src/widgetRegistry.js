
// Central widget registry — Sprint 4 default widgets.
// To add a widget: import your component and push to this array.
// Each entry: { id, label, Component, route }

import RulesManager from './widgets/RulesManager';
import ScanLog from './widgets/ScanLog';
import Stats from './widgets/Stats';
import SetupGuide from './widgets/SetupGuide';

const widgetRegistry = [
  {
    id: 'stats',
    label: 'Overview',
    route: '/',
    Component: Stats,
  },
  {
    id: 'rules',
    label: 'Rules',
    route: '/rules',
    Component: RulesManager,
  },
  {
    id: 'logs',
    label: 'Logs',
    route: '/logs',
    Component: ScanLog,
  },
  {
    id: 'setup',
    label: 'Setup Guide',
    route: '/setup',
    Component: SetupGuide,
  },
];

export default widgetRegistry;

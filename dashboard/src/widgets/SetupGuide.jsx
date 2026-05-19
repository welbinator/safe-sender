
import styles from './SetupGuide.module.css';

const STEPS = [
  {
    number: 1,
    title: 'Sign in and add your domain',
    body: 'When you signed up with Google, we captured your Google Workspace domain automatically. You can verify which domain is registered under Account → Domain.',
  },
  {
    number: 2,
    title: 'Set up your outbound gateway in Google Workspace Admin',
    body: (
      <>
        <ol>
          <li>Go to <strong>admin.google.com</strong></li>
          <li>Navigate to <strong>Apps → Google Workspace → Gmail → Routing</strong></li>
          <li>Under <strong>Outbound Gateway</strong>, click <em>Configure</em></li>
          <li>Enter the gateway address: <code>smtp.sendersafety.com</code></li>
          <li>Click <strong>Save</strong></li>
        </ol>
        <p>Once saved, all outbound email from your domain routes through Sender Safety for scanning.</p>
      </>
    ),
  },
  {
    number: 3,
    title: 'Add your first keyword rules',
    body: 'Go to the Rules page and add the words or phrases you want to flag. For example: "social security", "account number", "wire transfer". Each rule can match the subject, body, or both.',
  },
  {
    number: 4,
    title: 'Send a test email',
    body: 'Send an email from your Google Workspace account that contains one of your blocked keywords. It should bounce back with a rejection message. Then check the Logs page — you should see it appear as "blocked".',
  },
  {
    number: 5,
    title: "You're live",
    body: 'Every outbound email from your domain is now being scanned. Check the Overview page for daily stats and the Logs page for a full audit trail.',
  },
];

export default function SetupGuide() {
  return (
    <div className={styles.container}>
      <h1 className={styles.title}>Setup Guide</h1>
      <p className={styles.intro}>
        Get Sender Safety protecting your Google Workspace outbound email in under 10 minutes.
      </p>

      <div className={styles.steps}>
        {STEPS.map(step => (
          <div key={step.number} className={styles.step}>
            <div className={styles.stepNumber}>{step.number}</div>
            <div className={styles.stepContent}>
              <h2 className={styles.stepTitle}>{step.title}</h2>
              <div className={styles.stepBody}>{step.body}</div>
            </div>
          </div>
        ))}
      </div>

      <div className={styles.note}>
        <strong>Need help?</strong> Email us at <a href="mailto:support@sendersafety.com">support@sendersafety.com</a>
      </div>
    </div>
  );
}

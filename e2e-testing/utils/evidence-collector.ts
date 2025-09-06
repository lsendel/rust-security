import { Page } from '@playwright/test';
import fs from 'fs-extra';
import path from 'path';

export class EvidenceCollector {
  private testName: string;
  private evidenceDir: string;

  constructor(testName: string) {
    this.testName = testName.replace(/[^a-zA-Z0-9]/g, '-');
    this.evidenceDir = path.join('evidence', this.testName);
  }

  async setup(): Promise<void> {
    await fs.ensureDir(this.evidenceDir);
  }

  async captureScreenshot(page: Page, step: string): Promise<string> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `${step}-${timestamp}.png`;
    const filepath = path.join(this.evidenceDir, filename);
    
    await page.screenshot({ 
      path: filepath, 
      fullPage: true 
    });
    
    return filepath;
  }

  async captureVideo(page: Page): Promise<string | null> {
    const video = page.video();
    if (!video) return null;
    
    const videoPath = await video.path();
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const newPath = path.join(this.evidenceDir, `video-${timestamp}.webm`);
    
    await fs.copy(videoPath, newPath);
    return newPath;
  }

  async captureNetworkLogs(page: Page): Promise<string> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `network-${timestamp}.json`;
    const filepath = path.join(this.evidenceDir, filename);
    
    // This would need to be implemented with network request tracking
    const logs = { message: 'Network logging not implemented yet' };
    await fs.writeJson(filepath, logs, { spaces: 2 });
    
    return filepath;
  }

  async saveTestResult(result: any): Promise<string> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `result-${timestamp}.json`;
    const filepath = path.join(this.evidenceDir, filename);
    
    await fs.writeJson(filepath, result, { spaces: 2 });
    return filepath;
  }

  getEvidenceDir(): string {
    return this.evidenceDir;
  }
}

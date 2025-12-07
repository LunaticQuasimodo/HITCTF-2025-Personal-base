import { NextResponse } from 'next/server';
import puppeteer from 'puppeteer';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const queryString = searchParams.toString();
  const targetUrl = `http://127.0.0.1:3000/?${queryString}`;

  try {
    const browser = await puppeteer.launch({
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/chromium-browser',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--js-flags=--noexpose_wasm,--jitless'
      ],
      headless: true,
    });

    const page = await browser.newPage();
    
    page.setDefaultTimeout(10000);

    try {
      const response = await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 8000 });
      console.log(`Page loaded with status: ${response?.status()}`);
      
      const title = await page.title();
      console.log(`Page title: ${title}`);

      await new Promise(r => setTimeout(r, 5000));
    } catch (e) {
      console.error('Page navigation error:', e);
    } finally {
      await browser.close();
    }

    return NextResponse.json({ message: 'Bot Visited!' });
  } catch (error) {
    console.error('Bot error:', error);
    return NextResponse.json({ error: 'Bot failed' }, { status: 500 });
  }
}

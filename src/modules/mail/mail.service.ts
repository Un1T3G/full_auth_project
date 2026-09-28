import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  private transporter: nodemailer.Transporter | null = null;
  private readonly frontendUrl: string;

  constructor(private readonly configService: ConfigService) {
    this.frontendUrl = this.configService.get<string>('FRONTEND_URL') || 'http://localhost:3000';
    this.initTransporter();
  }

  private async initTransporter() {
    const host = this.configService.get<string>('SMTP_HOST');
    const port = Number(this.configService.get<number>('SMTP_PORT')) || 587;
    const user = this.configService.get<string>('SMTP_USER');
    const pass = this.configService.get<string>('SMTP_PASS');

    if (host && user && pass) {
      this.transporter = nodemailer.createTransport({
        host,
        port,
        secure: port === 465,
        auth: { user, pass },
      });
      this.logger.log(`Configured SMTP transporter with host: ${host}`);
    } else {
      // In development, fallback to console preview if SMTP is not provided
      this.logger.log('SMTP credentials not provided. Mail service will log preview URLs to console.');
    }
  }

  async sendVerificationEmail(email: string, token: string): Promise<void> {
    const verifyUrl = `${this.frontendUrl}/auth/verify-email?token=${token}`;
    const subject = 'Confirm your email address';
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
        <h2 style="color: #333;">Email Verification</h2>
        <p>Thank you for registering. Please click the button below to verify your email address:</p>
        <div style="margin: 25px 0;">
          <a href="${verifyUrl}" style="background-color: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
            Verify Email
          </a>
        </div>
        <p style="color: #666; font-size: 14px;">Or copy and paste this link in your browser:</p>
        <p style="color: #4f46e5; font-size: 13px; word-break: break-all;">${verifyUrl}</p>
        <p style="color: #999; font-size: 12px; margin-top: 30px;">This link will expire in 24 hours.</p>
      </div>
    `;

    await this.sendMail(email, subject, html);
  }

  async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    const resetUrl = `${this.frontendUrl}/auth/reset-password?token=${token}`;
    const subject = 'Reset your password';
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
        <h2 style="color: #333;">Password Reset Request</h2>
        <p>We received a request to reset your password. Click the button below to set a new password:</p>
        <div style="margin: 25px 0;">
          <a href="${resetUrl}" style="background-color: #ef4444; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
            Reset Password
          </a>
        </div>
        <p style="color: #666; font-size: 14px;">Or copy and paste this link in your browser:</p>
        <p style="color: #ef4444; font-size: 13px; word-break: break-all;">${resetUrl}</p>
        <p style="color: #999; font-size: 12px; margin-top: 30px;">This link is valid for 20 minutes only. If you did not make this request, you can safely ignore this email.</p>
      </div>
    `;

    await this.sendMail(email, subject, html);
  }

  private async sendMail(to: string, subject: string, html: string): Promise<void> {
    const from = this.configService.get<string>('MAIL_FROM') || 'noreply@fullauth.local';

    if (this.transporter) {
      try {
        await this.transporter.sendMail({ from, to, subject, html });
        this.logger.log(`Sent email to ${to}: "${subject}"`);
      } catch (error) {
        this.logger.error(`Failed to send email to ${to}:`, error);
      }
    } else {
      this.logger.log(`\n[EMAIL SIMULATION] ------------------------------`);
      this.logger.log(`To: ${to}`);
      this.logger.log(`Subject: ${subject}`);
      this.logger.log(`Preview link in HTML:`);
      const linkMatch = html.match(/href="([^"]+)"/);
      if (linkMatch) {
        this.logger.log(`Link: ${linkMatch[1]}`);
      }
      this.logger.log(`-------------------------------------------------\n`);
    }
  }
}
